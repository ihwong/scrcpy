#include "stream.h"

#include <assert.h>
#include <libavformat/avformat.h>
#include <libavutil/time.h>
#include <SDL2/SDL_events.h>
#include <SDL2/SDL_mutex.h>
#include <SDL2/SDL_thread.h>
#include <unistd.h>

#include "config.h"
#include "compat.h"
#include "decoder.h"
#include "events.h"
#include "recorder.h"
#include "util/buffer_util.h"
#include "util/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <fcntl.h>

#define BUFSIZE 0x10000

#define HEADER_SIZE 14
#define NO_PTS UINT64_C(-1)

static bool
stream_recv_packet(struct stream *stream, AVPacket *packet) {
    // The video stream contains raw packets, without time information. When we
    // record, we retrieve the timestamps separately, from a "meta" header
    // added by the server before each raw packet.
    //
    // The "meta" header length is 12 bytes:
    // [. . . . . . . .|. . . .]. . . . . . . . . . . . . . . ...
    //  <-------------> <-----> <-----------------------------...
    //        PTS        packet        raw packet
    //                    size
    //
    // It is followed by <packet_size> bytes containing the packet/frame.

  unsigned char rtp_header[14];

  uint16_t fragment_trace = 0x0000; // used ONLY for detecting position
  unsigned char position = 0; // 0 full packet, 1 first packet, 2 middle packet, 3 last packet, -1 error

  uint32_t timestamp;
  unsigned int len;

  // total bytes of each recv()
  int recv_bytes;
  
  // buffer for receiving data
  unsigned char buffer[4096]; // use unsigned char to prevent "ffffffe0" and so on (we want "e0")

    // parser for RTP header
    recv_bytes = recv(stream->socket, rtp_header, 14, 0);
    if (recv_bytes == 0) {
      printf("connection terminated by server.\n");
      exit(0);
    }

    for (int i = 0; i < 14; i++) {
      printf("%02x ", rtp_header[i]);
    }
    printf("\n");

    fragment_trace = (fragment_trace << 8) | rtp_header[1]; // previous rtp_header[1] and current rtp_header[1]
    
    /* packet fragment parser */
    // (previous packet, current packet)
    // 00 61 1st of fragment
    // 00 e1 full packet
    // 61 61 middle of fragment
    // 61 e1 last of fragment
    // e1 61 1st of fragment
    // e1 e1 full packet

    switch(fragment_trace) {
    case 0x00e1: case 0xe1e1: // one full packet
      position = 0;
      break;
    case 0x0061: case 0xe161: // first packet of fragmented data
      position = 1;
      break;
    case 0x6161: // middle packet of fragmented data
      position = 2;
      break;
    case 0x61e1: // last packet of fragmented data
      position = 3;
      break;
    default: // error
      printf("something's wrong :(\n");
      position = -1;
      break;
    }

    timestamp = (rtp_header[4] << 24) | (rtp_header[5] << 16) | (rtp_header[6] << 8) | (rtp_header[7]);
    len = (rtp_header[12] << 8 | rtp_header[13]) - 14; // 14 = rtp header
    
    // uint64_t pts = buffer_read64be(rtp_header);
    // uint16_t len = buffer_read16be(&rtp_header[12]) - 14;
    // assert(pts == NO_PTS || (pts & 0x8000000000000000) == 0);
    assert(len);

    // LOGI("pts = %lu", pts);
    LOGI("len = %u", len);

    
    if (av_new_packet(packet, len)) {
        LOGE("Could not allocate packet");
        return false;
    }

    ssize_t r = net_recv_all(stream->socket, packet->data, len);
    if (r < 0 || ((uint32_t) r) < len) {
        av_packet_unref(packet);
        return false;
    }

    // packet->pts = pts != NO_PTS ? (int64_t) pts : AV_NOPTS_VALUE;

    return true;
}

static void
notify_stopped(void) {
    SDL_Event stop_event;
    stop_event.type = EVENT_STREAM_STOPPED;
    SDL_PushEvent(&stop_event);
}

static bool
process_config_packet(struct stream *stream, AVPacket *packet) {
    if (stream->recorder && !recorder_push(stream->recorder, packet)) {
        LOGE("Could not send config packet to recorder");
        return false;
    }
    return true;
}

static bool
process_frame(struct stream *stream, AVPacket *packet) {
    if (stream->decoder && !decoder_push(stream->decoder, packet)) {
        return false;
    }

    if (stream->recorder) {
        packet->dts = packet->pts;

        if (!recorder_push(stream->recorder, packet)) {
            LOGE("Could not send packet to recorder");
            return false;
        }
    }

    return true;
}

static bool
stream_parse(struct stream *stream, AVPacket *packet) {
    uint8_t *in_data = packet->data;
    int in_len = packet->size;
    uint8_t *out_data = NULL;
    int out_len = 0;
    int r = av_parser_parse2(stream->parser, stream->codec_ctx,
                             &out_data, &out_len, in_data, in_len,
                             AV_NOPTS_VALUE, AV_NOPTS_VALUE, -1);

    // PARSER_FLAG_COMPLETE_FRAMES is set
    assert(r == in_len);
    (void) r;
    assert(out_len == in_len);

    if (stream->parser->key_frame == 1) {
        packet->flags |= AV_PKT_FLAG_KEY;
    }

    bool ok = process_frame(stream, packet);
    if (!ok) {
        LOGE("Could not process frame");
        return false;
    }

    return true;
}

static bool
stream_push_packet(struct stream *stream, AVPacket *packet) {
    bool is_config = packet->pts == AV_NOPTS_VALUE;

    // A config packet must not be decoded immetiately (it contains no
    // frame); instead, it must be concatenated with the future data packet.
    if (stream->has_pending || is_config) {
        size_t offset;
        if (stream->has_pending) {
            offset = stream->pending.size;
            if (av_grow_packet(&stream->pending, packet->size)) {
                LOGE("Could not grow packet");
                return false;
            }
        } else {
            offset = 0;
            if (av_new_packet(&stream->pending, packet->size)) {
                LOGE("Could not create packet");
                return false;
            }
            stream->has_pending = true;
        }

        memcpy(stream->pending.data + offset, packet->data, packet->size);

        if (!is_config) {
            // prepare the concat packet to send to the decoder
            stream->pending.pts = packet->pts;
            stream->pending.dts = packet->dts;
            stream->pending.flags = packet->flags;
            packet = &stream->pending;
        }
    }

    if (is_config) {
        // config packet
        bool ok = process_config_packet(stream, packet);
        if (!ok) {
            return false;
        }
    } else {
        // data packet
        bool ok = stream_parse(stream, packet);

        if (stream->has_pending) {
            // the pending packet must be discarded (consumed or error)
            stream->has_pending = false;
            av_packet_unref(&stream->pending);
        }

        if (!ok) {
            return false;
        }
    }
    return true;
}

static int
run_stream(void *data) {
    struct stream *stream = data;

    AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_H264);
    if (!codec) {
        LOGE("H.264 decoder not found");
        goto end;
    }

    stream->codec_ctx = avcodec_alloc_context3(codec);
    if (!stream->codec_ctx) {
        LOGC("Could not allocate codec context");
        goto end;
    }

    if (stream->decoder && !decoder_open(stream->decoder, codec)) {
        LOGE("Could not open decoder");
        goto finally_free_codec_ctx;
    }

    if (stream->recorder) {
        if (!recorder_open(stream->recorder, codec)) {
            LOGE("Could not open recorder");
            goto finally_close_decoder;
        }

        if (!recorder_start(stream->recorder)) {
            LOGE("Could not start recorder");
            goto finally_close_recorder;
        }
    }

    stream->parser = av_parser_init(AV_CODEC_ID_H264);
    if (!stream->parser) {
        LOGE("Could not initialize parser");
        goto finally_stop_and_join_recorder;
    }

    // We must only pass complete frames to av_parser_parse2()!
    // It's more complicated, but this allows to reduce the latency by 1 frame!
    stream->parser->flags |= PARSER_FLAG_COMPLETE_FRAMES;

    LOGI("HERE COMES!");

    for ( ; ; ) {
    AVPacket packet;
    bool ok = stream_recv_packet(stream, &packet);
    if (!ok) {
      // end of stream
      break;
    }

    ok = stream_push_packet(stream, &packet);
    av_packet_unref(&packet);
    if (!ok) {
      // cannot process packet (error already logged)
      break;
    }
    }

    LOGD("End of frames");

    if (stream->has_pending) {
        av_packet_unref(&stream->pending);
    }

    av_parser_close(stream->parser);
finally_stop_and_join_recorder:
    if (stream->recorder) {
        recorder_stop(stream->recorder);
        LOGI("Finishing recording...");
        recorder_join(stream->recorder);
    }
finally_close_recorder:
    if (stream->recorder) {
        recorder_close(stream->recorder);
    }
finally_close_decoder:
    if (stream->decoder) {
        decoder_close(stream->decoder);
    }
finally_free_codec_ctx:
    avcodec_free_context(&stream->codec_ctx);
end:
    notify_stopped();
    return 0;
}

void
stream_init(struct stream *stream, socket_t msocket,
            struct decoder *decoder, struct recorder *recorder) {
  // stream->socket = msocket;
    stream->decoder = decoder,
    stream->recorder = recorder;
    stream->has_pending = false;
      struct sockaddr_in server_addr;

  printf("control_socket socket() try\n");
  if ((msocket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    printf("control_socket socket() failed\n");
    close(msocket);
    exit(1);
  }
  printf("control_socket socket() success\n");

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr("192.168.0.100");
  server_addr.sin_port = htons(atoi("10000"));

  printf("control_socket connect() try\n");
  for ( ; ; ) {
    if (connect(msocket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
      printf("control_socket connect() failed\n");
    }
    else {
      break;
    }
  }
  printf("control_socket connect() success\n");
  stream->socket = msocket;
  LOGI("video_socket ok!");
}

bool
stream_start(struct stream *stream) {
    LOGD("Starting stream thread");

    stream->thread = SDL_CreateThread(run_stream, "stream", stream);
    if (!stream->thread) {
        LOGC("Could not start stream thread");
        return false;
    }
    LOGI("stream_start() ok!!");
    return true;
}

void
stream_stop(struct stream *stream) {
    if (stream->decoder) {
        decoder_interrupt(stream->decoder);
    }
}

void
stream_join(struct stream *stream) {
    SDL_WaitThread(stream->thread, NULL);
}

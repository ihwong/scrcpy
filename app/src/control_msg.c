#include "control_msg.h"

#include <assert.h>
#include <string.h>

#include "config.h"
#include "util/buffer_util.h"
#include "util/log.h"
#include "util/str_util.h"

static void
write_position(uint8_t *buf, const struct position *position) {
    buffer_write32be(&buf[0], position->point.x);
    buffer_write32be(&buf[4], position->point.y);
    buffer_write16be(&buf[8], position->screen_size.width);
    buffer_write16be(&buf[10], position->screen_size.height);
}

// write length (2 bytes) + string (non nul-terminated)
static size_t
write_string(const char *utf8, size_t max_len, unsigned char *buf) {
    size_t len = utf8_truncation_index(utf8, max_len);
    buffer_write16be(buf, (uint16_t) len);
    memcpy(&buf[2], utf8, len);
    return 2 + len;
}

static uint16_t
to_fixed_point_16(float f) {
    assert(f >= 0.0f && f <= 1.0f);
    uint32_t u = f * 0x1p16f; // 2^16
    if (u >= 0xffff) {
        u = 0xffff;
    }
    return (uint16_t) u;
}

size_t
control_msg_serialize(const struct control_msg *msg, unsigned char *buf) {
    buf[0] = msg->type;
    switch (msg->type) {
        case CONTROL_MSG_TYPE_INJECT_KEYCODE:
            buf[1] = msg->inject_keycode.action;
            buffer_write32be(&buf[2], msg->inject_keycode.keycode);
            buffer_write32be(&buf[6], msg->inject_keycode.metastate);
	    printf("%d %d %d %d\n", msg->type, msg->inject_keycode.action, msg->inject_keycode.keycode + 68, msg->inject_keycode.metastate);
	    if ((buf[1] == 0) && (msg->inject_keycode.keycode == 67)) {
		sprintf(buf, "key:delete,5\n");
		printf("%s", buf);
		return 13;
	    }
	    if ((buf[1] == 0) && (msg->inject_keycode.keycode == 62)) {
		sprintf(buf, "key: ,5\n");
		printf("%s", buf);
		return 8;
	    }
	    if ((buf[1] == 0) && (msg->inject_keycode.metastate == 2097152)) { // abc
		sprintf(buf, "key:%c,5\n", msg->inject_keycode.keycode + 68);
		printf("%s", buf);
		return 8;
	    }
	    if ((buf[1] == 0) && (msg->inject_keycode.metastate == 3145728)) { // ABC
		sprintf(buf, "key:%c,5\n", msg->inject_keycode.keycode + 36);
		printf("%s", buf);
		return 8;
	    }
            return -1;
        case CONTROL_MSG_TYPE_INJECT_TEXT: {
            size_t len =
                write_string(msg->inject_text.text,
                             CONTROL_MSG_INJECT_TEXT_MAX_LENGTH, &buf[1]);
	    printf("%c\n", msg->inject_text.text[0]);
	    sprintf(buf, "key:%c,5\n", msg->inject_text.text[0]);
            return 8;
        }
        case CONTROL_MSG_TYPE_INJECT_TOUCH_EVENT:
            buf[1] = msg->inject_touch_event.action;
            buffer_write64be(&buf[2], msg->inject_touch_event.pointer_id);
            write_position(&buf[10], &msg->inject_touch_event.position);
            uint16_t pressure =
                to_fixed_point_16(msg->inject_touch_event.pressure);
            buffer_write16be(&buf[22], pressure);
            buffer_write32be(&buf[24], msg->inject_touch_event.buttons);
	    
	    uint8_t status = buf[1]; // 0 click, 1 release, 2 drag
	    int payload_length = 4; // ; ; 0 \n
	    uint16_t pos_x = (buf[12] << 8) | buf[13];
	    uint16_t pos_y = (buf[16] << 8) | buf[17];
	    if (pos_x < 10) {
	      payload_length += 1;
	    }
	    else if (pos_x < 100) {
	      payload_length += 2;
	    }
	    else if (pos_x < 1000) {
	      payload_length += 3;
	    }
	    else {
	      payload_length += 4;
	    }
	    if (pos_y < 10) {
	      payload_length += 1;
	    }
	    else if (pos_y < 100) {
	      payload_length += 2;
	    }
	    else if (pos_y < 1000) {
	      payload_length += 3;
	    }
	    else {
	      payload_length += 4;
	    }
	    sprintf(buf, "%d;%d;%u\n", pos_x, pos_y, status);
	    printf("payload = %s", buf);
            return payload_length;// 28;
        case CONTROL_MSG_TYPE_INJECT_SCROLL_EVENT:
            write_position(&buf[1], &msg->inject_scroll_event.position);
            buffer_write32be(&buf[13],
                             (uint32_t) msg->inject_scroll_event.hscroll);
            buffer_write32be(&buf[17],
                             (uint32_t) msg->inject_scroll_event.vscroll);
            return 21;
        case CONTROL_MSG_TYPE_SET_CLIPBOARD: {
            buf[1] = !!msg->set_clipboard.paste;
            size_t len = write_string(msg->set_clipboard.text,
                                      CONTROL_MSG_CLIPBOARD_TEXT_MAX_LENGTH,
                                      &buf[2]);
            return 2 + len;
        }
        case CONTROL_MSG_TYPE_SET_SCREEN_POWER_MODE:
            buf[1] = msg->set_screen_power_mode.mode;
            return 2;
        case CONTROL_MSG_TYPE_BACK_OR_SCREEN_ON:
        case CONTROL_MSG_TYPE_EXPAND_NOTIFICATION_PANEL:
        case CONTROL_MSG_TYPE_COLLAPSE_NOTIFICATION_PANEL:
        case CONTROL_MSG_TYPE_GET_CLIPBOARD:
        case CONTROL_MSG_TYPE_ROTATE_DEVICE:
            // no additional data
            return 1;
        default:
            LOGW("Unknown message type: %u", (unsigned) msg->type);
            return 0;
    }
}

void
control_msg_destroy(struct control_msg *msg) {
    switch (msg->type) {
        case CONTROL_MSG_TYPE_INJECT_TEXT:
            SDL_free(msg->inject_text.text);
            break;
        case CONTROL_MSG_TYPE_SET_CLIPBOARD:
            SDL_free(msg->set_clipboard.text);
            break;
        default:
            // do nothing
            break;
    }
}

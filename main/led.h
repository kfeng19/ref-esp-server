#define BLINK_GPIO CONFIG_BLINK_GPIO

static led_strip_handle_t led_strip;

void configure_led();

void control_led(bool);
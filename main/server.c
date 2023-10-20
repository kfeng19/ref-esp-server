#include <string.h>
#include "esp_log.h"
#include "nvs_flash.h"
// #include "lwip/err.h"
#include "lwip/sys.h"

#include "my_wifi.h"
#include "my_http.h"
#include "var.h"

/* A simple example that demonstrates how to create GET and POST
 * handlers for the web server.
 */

void app_main(void)
{
    static httpd_handle_t server = NULL;
    //Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_LOGI(TAG, "ESP_WIFI_MODE_STA");
    wifi_init_sta();
        /* Start the server for the first time */
    server = start_webserver();

    while (server) {
        sleep(5);
    }
}
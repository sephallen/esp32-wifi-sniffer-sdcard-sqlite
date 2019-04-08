#include <Arduino.h>
#include "WiFi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/timers.h"
#include <NTPClient.h>
#include <WiFiUdp.h>
#include <Wire.h> 
#include <RtcDS3231.h>
#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <SPI.h>
#include <FS.h>
#include "SD.h"
#include "freertos/ringbuf.h"

extern "C" {
  #include <esp_wifi.h>
}

#define WIFI_CHANNEL_MIN                1           // start channel number where scan begings
#define	WIFI_CHANNEL_MAX                13          // total channel number to scan
#define WIFI_MY_COUNTRY                 "EU"        // select locale for Wifi RF settings
#define	WIFI_CHANNEL_SWITCH_INTERVAL    1000        // channel switch in milliseconds
#define NTP_OFFSET                      0 * 60 * 60 // In seconds
#define NTP_INTERVAL                    60 * 1000   // In miliseconds
#define NTP_ADDRESS                     "0.uk.pool.ntp.org"
#define countof(a) (sizeof(a) / sizeof(a[0]))

const char* ssid = "behold";
const char* password = "password";

uint8_t channel = WIFI_CHANNEL_MIN;
TimerHandle_t WifiChanTimer;
RingbufHandle_t packetRingbuf;
WiFiUDP ntpUDP;
NTPClient timeClient(ntpUDP, NTP_ADDRESS, NTP_OFFSET, NTP_INTERVAL);
RtcDS3231<TwoWire> Rtc(Wire);
RtcDateTime currTime;
sqlite3 *db1;

static wifi_country_t wifi_country = {WIFI_MY_COUNTRY, WIFI_CHANNEL_MIN, WIFI_CHANNEL_MAX, 100, WIFI_COUNTRY_POLICY_MANUAL};

typedef struct {
  unsigned frame_ctrl : 16;
  unsigned duration_id : 16;
  uint8_t addr1[6]; // receiver address
  uint8_t addr2[6]; // sender address
  uint8_t addr3[6]; // filtering address
  unsigned sequence_ctrl : 16;
  uint8_t addr4[6]; // optional
} wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0]; // network data ended with 4 bytes csum (CRC32)
} wifi_ieee80211_packet_t;

int openDb(const char *filename, sqlite3 **db) {
  int rc = sqlite3_open(filename, db);
  return rc;
}

char *zErrMsg = 0;

// using IRAM_:ATTR here to speed up callback function
void IRAM_ATTR wifi_sniffer_packet_handler(void *buffer, wifi_promiscuous_pkt_type_t type) {
  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buffer;
  const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
  const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;
  
  char channelString[3];
  sprintf(channelString, "%d", channel);

  char rssiString[20];
  sprintf(rssiString, "%d", ppkt->rx_ctrl.rssi);

  char receiverString[] = "00:00:00:00:00:00";
  sprintf(receiverString, "%02x:%02x:%02x:%02x:%02x:%02x", hdr->addr1[0], hdr->addr1[1], hdr->addr1[2], hdr->addr1[3], hdr->addr1[4], hdr->addr1[5]);

  char senderString[] = "00:00:00:00:00:00";
  sprintf(senderString, "%02x:%02x:%02x:%02x:%02x:%02x", hdr->addr2[0], hdr->addr2[1], hdr->addr2[2], hdr->addr2[3], hdr->addr2[4], hdr->addr2[5]);

  char filteringString[] = "00:00:00:00:00:00";
  sprintf(filteringString, "%02x:%02x:%02x:%02x:%02x:%02x", hdr->addr3[0], hdr->addr3[1], hdr->addr3[2], hdr->addr3[3], hdr->addr3[4], hdr->addr3[5]);

  char typeString[20];
  sprintf(typeString, "%d", type);

  char dateString[20];
  snprintf_P(dateString, 
    countof(dateString),
    PSTR("%02u/%02u/%04u %02u:%02u:%02u"),
    currTime.Day(),
    currTime.Month(),
    currTime.Year(),
    currTime.Hour(),
    currTime.Minute(),
    currTime.Second()
  );

  char sql[1024];
  sprintf(sql, "INSERT INTO found VALUES (%s,%s,'%s','%s','%s',%s,'%s');", channelString, rssiString, receiverString, senderString, filteringString, typeString, dateString);

  xRingbufferSend(packetRingbuf, sql, sizeof(sql), 0);
}

// Software-timer driven Wifi channel rotation callback function
void switchWifiChannel(TimerHandle_t xTimer) {
  channel = (channel % WIFI_CHANNEL_MAX) + 1; // rotate channel 1..WIFI_CHANNEL_MAX
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

void getTime() {
  uint8_t retries = 0;

  WiFi.begin(ssid, password);

  // Wait for 30 seconds before giving up
  while (WiFi.status() != WL_CONNECTED && retries < 60) {
    delay(500);
    retries++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    timeClient.begin();
    timeClient.update();
    unsigned long epochTime = timeClient.getEpochTime()-946684800UL;
    Rtc.SetDateTime(epochTime); 
    WiFi.disconnect();
  }

  String formattedTime = timeClient.getFormattedTime();
}

static void IRAM_ATTR sqliteTask(void *arg) {
	while(1) {
		size_t len;
    char *sql = (char *)xRingbufferReceive(packetRingbuf, &len, portMAX_DELAY);
    if (sql != NULL) {
      sqlite3_initialize();
      openDb("/sd/wifisniffer.db", &db1);
      int rc = sqlite3_exec(db1, sql, 0, (void*)"", &zErrMsg);
      if (rc != SQLITE_OK) {
        sqlite3_free(zErrMsg);
      }
      sqlite3_close(db1);
      vRingbufferReturnItem(packetRingbuf, sql);
    }
	}
}

void setup() {

  Serial.begin(115200);
  Rtc.Begin();
  getTime();
  
  SPI.begin();
  SD.begin();

  packetRingbuf = xRingbufferCreate(12*1024, RINGBUF_TYPE_NOSPLIT);

  wifi_promiscuous_filter_t filter = {.filter_mask = WIFI_PROMIS_FILTER_MASK_ALL};
  wifi_init_config_t wificfg = WIFI_INIT_CONFIG_DEFAULT();
  wificfg.nvs_enable = 0;
  wificfg.wifi_task_core_id = 0;
  esp_wifi_init(&wificfg);
  esp_wifi_set_country(&wifi_country);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_stop();
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);

  xTaskCreatePinnedToCore(sqliteTask, "sqliteTask", 8192, NULL, 3, NULL, 1);

  // setup wifi channel rotation timer
  WifiChanTimer = xTimerCreate("WifiChannelTimer", pdMS_TO_TICKS(WIFI_CHANNEL_SWITCH_INTERVAL), pdTRUE, (void *)0, switchWifiChannel);
  assert(WifiChanTimer);
  xTimerStart(WifiChanTimer, 0);

}

void loop() {
  // Only get time from RTC once per second, issues occur if trying to ask more frequently
  currTime = Rtc.GetDateTime();
  delay(1000);
}
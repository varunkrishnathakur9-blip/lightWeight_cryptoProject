/*
 * Phase 2 firmware scaffold for Arduino Mega2560 + R307/R307S.
 *
 * Purpose:
 * - Read fingerprint events from R307 over UART (Serial1).
 * - Emit newline-delimited JSON events over USB Serial to PC edge bridge.
 *
 * Notes:
 * - This scaffold supports two modes:
 *   1) R307 mode (requires Adafruit Fingerprint Sensor library).
 *   2) Simulated event mode (compile-time fallback for bench bring-up).
 * - PC edge bridge script: experiments/phase2_edge_bridge.py
 */

#include <Arduino.h>

// Uncomment to enable real sensor mode after installing Adafruit Fingerprint Sensor Library.
// #define USE_R307_SENSOR

#ifdef USE_R307_SENSOR
#include <Adafruit_Fingerprint.h>
HardwareSerial &sensorSerial = Serial1;  // Mega2560 Serial1: RX1=19, TX1=18
Adafruit_Fingerprint finger = Adafruit_Fingerprint(&sensorSerial);
#endif

static const uint32_t USB_BAUD = 115200;
static const uint32_t SENSOR_BAUD = 57600;
static const uint32_t HEARTBEAT_MS = 3000;
static const uint32_t SIM_EVENT_INTERVAL_MS = 2000;

uint32_t g_seq = 0;
uint32_t g_lastHeartbeat = 0;
uint32_t g_lastSimEvent = 0;

static void emitEvent(const char *status, int fingerId, int confidence) {
  const unsigned long sensorTs = millis();
  Serial.print("{\"type\":\"sensor_event\",");
  Serial.print("\"seq\":");
  Serial.print(g_seq++);
  Serial.print(",\"status\":\"");
  Serial.print(status);
  Serial.print("\",");
  Serial.print("\"finger_id\":");
  Serial.print(fingerId);
  Serial.print(",\"confidence\":");
  Serial.print(confidence);
  Serial.print(",\"sensor_ts_ms\":");
  Serial.print(sensorTs);
  Serial.println("}");
}

static void emitHeartbeat() {
  Serial.print("{\"type\":\"heartbeat\",\"uptime_ms\":");
  Serial.print(millis());
  Serial.print(",\"seq\":");
  Serial.print(g_seq);
  Serial.print(",\"free_ram_bytes\":");
  extern int __heap_start, *__brkval;
  int v;
  int freeMem = (int)&v - (__brkval == 0 ? (int)&__heap_start : (int)__brkval);
  Serial.print(freeMem);
  Serial.println("}");
}

#ifdef USE_R307_SENSOR
static void pollR307() {
  uint8_t p = finger.getImage();
  if (p == FINGERPRINT_NOFINGER) {
    return;
  }
  if (p != FINGERPRINT_OK) {
    emitEvent("image_error", -1, 0);
    delay(80);
    return;
  }

  p = finger.image2Tz();
  if (p != FINGERPRINT_OK) {
    emitEvent("template_error", -1, 0);
    delay(80);
    return;
  }

  p = finger.fingerFastSearch();
  if (p == FINGERPRINT_OK) {
    emitEvent("match", finger.fingerID, finger.confidence);
  } else {
    emitEvent("no_match", -1, 0);
  }
  delay(120);
}
#else
static void emitSimulatedEvents() {
  const uint32_t now = millis();
  if (now - g_lastSimEvent >= SIM_EVENT_INTERVAL_MS) {
    g_lastSimEvent = now;
    emitEvent("simulated_match", 1, 80);
  }
}
#endif

void setup() {
  Serial.begin(USB_BAUD);
  while (!Serial) {
    ;
  }

#ifdef USE_R307_SENSOR
  sensorSerial.begin(SENSOR_BAUD);
  finger.begin(SENSOR_BAUD);
  if (!finger.verifyPassword()) {
    Serial.println("{\"type\":\"boot\",\"status\":\"sensor_not_found\"}");
  } else {
    Serial.println("{\"type\":\"boot\",\"status\":\"sensor_ready\"}");
  }
#else
  Serial.println("{\"type\":\"boot\",\"status\":\"sim_mode\"}");
#endif
}

void loop() {
  const uint32_t now = millis();

#ifdef USE_R307_SENSOR
  pollR307();
#else
  emitSimulatedEvents();
#endif

  if (now - g_lastHeartbeat >= HEARTBEAT_MS) {
    g_lastHeartbeat = now;
    emitHeartbeat();
  }

  // Optional: read ACK/NACK lines from PC edge bridge for diagnostics.
  if (Serial.available() > 0) {
    String line = Serial.readStringUntil('\n');
    line.trim();
    if (line.length() > 0) {
      Serial.print("{\"type\":\"bridge_ack\",\"msg\":\"");
      Serial.print(line);
      Serial.println("\"}");
    }
  }
}

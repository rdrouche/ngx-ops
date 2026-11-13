# Map

This feature is clearly a **gadget**... and therefore totally useful! 😄

It displays on a map, **in real time**, the geographic origin of the requests received by Nginx and identifies the type of visitor behind them:

* **Human**
* **Robot**

The information comes from the logs analyzed by **Nginx Analyzer Agent** and from IP address geolocation.

## Requirements

To use this feature, the following components must be configured:

* [**Nginx Analyzer Agent - NAA**](../nginx-analyzer.md)
* [**GeoIP**](../geoip.md)

NAA analyzes the requests and sends the necessary information to NGX Ops, while GeoIP determines their geographic location.

## Usage

The map is available from: **INTEGRATION → Map**

Requests then appear directly on the map with their geographic origin and their **Human / Robot** classification.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-027-map.png" width="800" />

> **Note:** the geolocation of an IP address remains approximate. The position displayed does not match the exact location of the user or server behind the request.

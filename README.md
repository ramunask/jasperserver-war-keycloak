# jasperserver-war-keycloak
JasperReports® Server 6.2.0 integration with Keycloak 1.9.1.Final via Spring Security and Open ID (OAuth) protocol.

### Changes

[x] Multi Tenancy
[ ] SAML
[ ] Single Sign Out

### Information

Client Adapter is: Spring Security with OpenID (OAuth)



## Requisition

* Keycloak 1.9.1 installed.
* JasperReports Server 6.2.0 installed.


## How to setup

 1. Register a new client **jasperserver** in Keycloak server, with details as below:
    - Client ID: jasperserver
    - Client Protocol: openid-connect
    - Access Type: confidential
    - Valid Redirect URIs: <JasperServer - Context Path>/*
    - Base URL: <JasperServer - Context Path>

 2. Update **master.json** in **jasperserver-war-keycloak** project, specially for this parameters:
    - realm (default: master)
    - realm-public-key
    - auth-server-url: <Keycloak - Host:Port>/auth
    - credentials {secret}: <Keycloak - 'jasperserver' client - Credentials - Secret>


## How to change realm

 1. Access the http://<HostName>:<Port>/jasperserver/?realm=<realm name>.
 2. The selected realm name will be stored in a cookie with name **realm**.


## Concerns

* SAML haven't been implemented, but looks like it can be done with:
  - Keycloak - SAML Adapter - General Adapter Config
  - Spring Securty SAML - Spring Security Integration

* Single Sign Out, currently only been implemented one way from JasperServer - Logout to Keycloak Server.
  To support a fully Single Sign Out, must implement Keycloak - User Guide - Javascript Adapter - Session status iframe.

* Spring Security Filter, currently this project follow the original JasperServer (as there's no original files that been override), which is Logout Filter continue with Pre-Authentication Filter.
  In the Keycloak documentation, it should be Pre-Authentication Filter continue with Logout Filter.


# Serverless NiFi connector for organization and user provisioning

This example demonstrates how to use NiFi API to command and control NiFi instance in order to facilitate the interaction with Single Sign-On with [AAC](https://github.com/scc-digitalhub/AAC) .

## AAC Client Application Configuration

For roles list  elaboration it is important to put the content of the file customClaims.js in the section Custom Claim Mapping Function of the NiFi Client App.
Make sure to change the value of the path 'components/' according to the needs of the NiFi component including also the customization of the role names corresponding to NiFi roles.

## NFi Configuration and integration

For detailed descriptions regarding NiFi configuration and integration with AAC OAUTH2 provider refer to [the documentation site](https://digitalhub.readthedocs.io/en/latest/docs/data/nifi.html)



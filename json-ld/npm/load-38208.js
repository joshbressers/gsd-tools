#!/usr/bin/env node

var jsonld = require('jsonld');
var jsonld_request = require('jsonld-request');

var ld_file = "../UVI-2021-38208.jsonld";

jsonld_request(ld_file, function(err, res, the_data) {
    console.log("Loading " + ld_file);
    var cve_url = the_data['cve'];

    console.log("Loading " + cve_url);
    jsonld_request(cve_url, function(err, res, cve_data) {
        var cve_id = cve_data['result']['CVE_Items'][0]['cve']['CVE_data_meta']['ID'];
        console.log("Found " + cve_id);
    });

});

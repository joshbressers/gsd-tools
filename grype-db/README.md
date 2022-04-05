# GrypeDB importer scripts

The Grype DB listing can be found here
https://toolbox-data.anchore.io/grype/databases/listing.json

The latest DB can be found by running
curl https://toolbox-data.anchore.io/grype/databases/listing.json | jq '.available."3"[0].url'

Download the tar file at that location.

For added fun, tar doesn't like files with a : in their name, which this
file will have. You have to run
`tar --force-local -x -f <filename>`



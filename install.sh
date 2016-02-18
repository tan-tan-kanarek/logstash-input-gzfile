#!/bin/bash

cd /opt/logstash-input-gzfile
gem build /opt/logstash-input-gzfile/logstash-input-file.gemspec
/opt/logstash/bin/plugin install /opt/logstash-input-gzfile/logstash-input-gzfile-1.0.0.gem

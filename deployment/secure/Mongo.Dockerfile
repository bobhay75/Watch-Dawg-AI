# The upstream server/shell remain pinned; unused helper code is removed.
FROM mongo:8.0@sha256:bdc216e9d5a6ec2cfdac789b5832fdab64cd32055f59885cae918a92de63c361
# No production volume is mounted during this build. These are image files.
# Do not replace this with deletion/pruning of database or evidence paths.
RUN rm -f /usr/local/bin/gosu /usr/local/bin/docker-entrypoint.sh \
      /usr/bin/bsondump /usr/bin/mongodump /usr/bin/mongoexport \
      /usr/bin/mongofiles /usr/bin/mongoimport /usr/bin/mongorestore \
      /usr/bin/mongostat /usr/bin/mongotop \
    && rm -rf /opt/js-yaml
# Root-only init scripts and automatic chown are intentionally unavailable.
USER 999:999
ENTRYPOINT []
CMD ["mongod", "--bind_ip_all"]

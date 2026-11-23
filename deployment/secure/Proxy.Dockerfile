# syntax=docker/dockerfile:1
FROM nginx:stable-alpine@sha256:caf4e1e032a20f9c3c5e28fc7f25ffd768ad8677b4975c54193075997b3a97e3
# Optional build-only CA; patched APK packages retain certificate verification.
RUN --mount=type=secret,id=package_ca \
    if [ -s /run/secrets/package_ca ]; then \
      SSL_CERT_FILE=/run/secrets/package_ca apk add --no-cache --upgrade libxslt=1.1.43-r4 zlib=1.4-r0; \
    else \
      apk add --no-cache --upgrade libxslt=1.1.43-r4 zlib=1.4-r0; \
    fi
COPY --chmod=0644 deployment/secure/nginx.conf /etc/nginx/nginx.conf
USER 101:101
ENTRYPOINT ["nginx", "-g", "daemon off;"]

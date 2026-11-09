FROM nginx:alpine
# Dev-only self-signed certificate for the HTTPS listener (generated at build; never reused elsewhere)
RUN apk add --no-cache openssl && openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=testtarget" \
      -keyout /etc/nginx/dev.key -out /etc/nginx/dev.crt && apk del openssl
COPY default.conf /etc/nginx/conf.d/default.conf
COPY index.html /usr/share/nginx/html/index.html
COPY dotenv /usr/share/nginx/html/.env

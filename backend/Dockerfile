FROM python:3.12-slim AS vendor
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
 && apt-get clean
COPY vendor/ /vendor-src/
RUN sh /vendor-src/fetch.sh /opt/vendor
RUN chmod -R a+rX /opt/vendor  # git temp dirs are 0700; scanner user must read

FROM python:3.12-slim
# nmap; testssl.sh deps (bash openssl procps bsdextrautils dnsutils); WeasyPrint libs + fontconfig
RUN apt-get update && apt-get install -y --no-install-recommends nmap bash openssl procps bsdextrautils bind9-dnsutils \
      libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 fontconfig \
 && apt-get clean && useradd --create-home scanner
COPY --from=vendor /opt/vendor /opt/vendor
RUN ln -s /opt/vendor/fonts /usr/share/fonts/plex && fc-cache -f \
 && ln -s /opt/vendor/testssl/testssl.sh /usr/local/bin/testssl.sh
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
USER scanner
EXPOSE 8000

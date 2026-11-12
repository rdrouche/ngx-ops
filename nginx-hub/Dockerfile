FROM node:22-alpine

ENV NODE_ENV=production \
    HUB_CONFIG=/config/hub.yml \
    HUB_DATA_DIR=/data \
    NODE_OPTIONS=--disable-warning=ExperimentalWarning

WORKDIR /app
# Aucune dépendance npm par défaut (SQLite via node:sqlite) : on copie uniquement le code applicatif.
COPY package.json server.js ./
COPY lib ./lib
COPY features ./features
COPY bin ./bin
COPY public ./public

# Version affichée (build global, #65) : ARG APP_VERSION du CI ; absente = valeur du code.
ARG APP_VERSION=""
ENV APP_VERSION=${APP_VERSION}

# Option PostgreSQL : docker compose build --build-arg WITH_PG=1 (installe uniquement le paquet « pg »).
ARG WITH_PG=0
RUN if [ "$WITH_PG" = "1" ]; then npm install --omit=dev --no-audit --no-fund --ignore-scripts pg@8 && npm cache clean --force; fi

# Utilisateur non privilégié ; /data est le seul répertoire inscriptible.
RUN addgroup -S hub && adduser -S -G hub -u 10001 hub \
 && mkdir -p /data /config && chown -R hub:hub /data && chmod 700 /data
USER hub

VOLUME ["/data"]
EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=4s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.HUB_PORT||8090)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]

FROM node:24-alpine

WORKDIR /app
COPY server.js .

EXPOSE 3345

CMD ["node", "server.js"]

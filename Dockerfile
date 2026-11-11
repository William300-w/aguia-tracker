FROM node:18-slim
WORKDIR /app
COPY package.json ./
ARG CACHE_BUST=2
RUN npm install --production && npm ls web-push && echo "web-push installed OK"
COPY . .
EXPOSE 3000
ENV PORT=3000
CMD ["node", "server.js"]

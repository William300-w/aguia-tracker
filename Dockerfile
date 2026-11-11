FROM node:18-slim
WORKDIR /app
COPY package.json ./
RUN npm install --production
RUN npm install web-push@3.6.7
COPY . .
EXPOSE 3000
ENV PORT=3000
CMD ["node", "server.js"]

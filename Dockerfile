FROM node:18-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --production
COPY . .
RUN mkdir -p /app/data
EXPOSE 3000
ENV PORT=3000
ENV DB_PATH=/app/data/aguia.db
CMD ["node", "server.js"]

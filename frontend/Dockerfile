FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402
WORKDIR /app
COPY package*.json ./
# `npm ci` installs exactly what package-lock.json pins, so an image rebuilt
# months later is the same image. `npm install` would silently drift.
RUN npm ci
COPY . .
EXPOSE 5173
CMD ["npm", "run", "dev"]

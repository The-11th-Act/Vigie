FROM node:26-alpine@sha256:0b36e8c136b94cd4fcf02188228e76c31ad5872eef3fec8cbd2eee500cfd9e80
WORKDIR /app
COPY package*.json ./
# `npm ci` installs exactly what package-lock.json pins, so an image rebuilt
# months later is the same image. `npm install` would silently drift.
RUN npm ci
COPY . .
EXPOSE 5173
CMD ["npm", "run", "dev"]

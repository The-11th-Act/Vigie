FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
# `npm ci` installs exactly what package-lock.json pins, so an image rebuilt
# months later is the same image. `npm install` would silently drift.
RUN npm ci
COPY . .
EXPOSE 5173
CMD ["npm", "run", "dev"]

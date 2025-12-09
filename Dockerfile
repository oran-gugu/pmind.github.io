FROM node:20-alpine

WORKDIR /usr/src/app

# Install dependencies first for better caching
COPY package.json ./
RUN npm install

# Copy application source
COPY public ./public
COPY src ./src
COPY astro.config.mjs tsconfig.json ./

EXPOSE 4000

CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "4000"]

# Dockerfile for react2shell-guard container scanning example
FROM node:20-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source
COPY dist/ ./dist/

# Set entrypoint
ENTRYPOINT ["node", "dist/cli/index.js"]

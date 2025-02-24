# Use an official Node.js runtime as a parent image
FROM node:20

# Set the working directory
WORKDIR /app

# Copy package files first (for efficient caching)
COPY package*.json ./
RUN npm install

# Copy the rest of the project files
COPY . .

# Build the project (if needed)
RUN npm run build

# Set up environment variables
ARG BACK_PORT
ENV BACK_PORT=${BACK_PORT}

# Expose the port from .env (default to 3000)
EXPOSE ${BACK_PORT}

# Run the application
CMD ["node", "dist/server.js"]

# Use an official Node.js runtime as a parent image
FROM node:16

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
ARG NODE_PORT
ENV NODE_PORT=${NODE_PORT}

# Expose the port from .env (default to 3000)
EXPOSE ${NODE_PORT}

# Run the application
CMD ["node", "dist/index.js"]

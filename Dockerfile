# Use a Node.js base image
FROM node:20-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    perl \
    wget \
    unzip \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies (skip scripts initially to avoid setup-tools failing without binaries)
RUN npm install --ignore-scripts

# Create bin directory
RUN mkdir -p bin

# Download Nuclei
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.10/nuclei_3.3.10_linux_amd64.zip -O /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip -d bin/ \
    && chmod +x bin/nuclei

# Download Subfinder
RUN wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_linux_amd64.zip -O /tmp/subfinder.zip \
    && unzip -o /tmp/subfinder.zip -d bin/ \
    && chmod +x bin/subfinder

# Copy source code
COPY . .

# Run the tool setup (clones sqlmap, etc.)
RUN node scripts/setup-tools.js

# Generate Prisma client
RUN npx prisma generate

# Build the Next.js app
RUN npm run build

# Expose port
EXPOSE 3000

# Start the application
CMD ["npm", "start"]

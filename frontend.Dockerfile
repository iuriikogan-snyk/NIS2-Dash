# Stage 1: Build the React application
FROM node:20-alpine AS builder
WORKDIR /app
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ .
RUN npm run build

# Stage 2: Serve the static files with Nginx
FROM nginx:1.27-alpine

# Copy the built static files from the builder stage
COPY --from=builder /app/build /usr/share/nginx/html

# Copy the snyk_export.csv file to the Nginx server's HTML directory
COPY frontend/public/snyk_export.csv /usr/share/nginx/html/snyk_export.csv

# Remove the default Nginx configuration file
RUN rm /etc/nginx/conf.d/default.conf

# Copy our custom Nginx configuration into the container
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf

# Expose port 80 to the Docker network
EXPOSE 80

# Start Nginx in the foreground
CMD ["nginx", "-g", "daemon off;"]

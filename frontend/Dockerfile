FROM node:20-alpine
WORKDIR /app
COPY package.json .
RUN npm install --no-audit --no-fund
COPY . .
ENV VITE_API_BASE=http://localhost:8000
EXPOSE 5173
CMD ["npm","run","dev","--","--host","0.0.0.0"]

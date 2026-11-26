FROM node:24-alpine AS builder
WORKDIR /app

COPY package.json tsconfig.base.json ./
COPY packages/rid-sdk/package.json packages/rid-sdk/tsconfig.json packages/rid-sdk/
COPY apps/id/package.json apps/id/tsconfig.json apps/id/

RUN npm install

COPY packages/rid-sdk/src packages/rid-sdk/src
COPY apps/id/src apps/id/src

RUN npm run build

FROM node:24-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV MW_RID_PORT=4480

COPY package.json ./
COPY packages/rid-sdk/package.json packages/rid-sdk/
COPY apps/id/package.json apps/id/
RUN npm install --omit=dev

COPY --from=builder /app/packages/rid-sdk/dist packages/rid-sdk/dist
COPY --from=builder /app/apps/id/dist apps/id/dist

EXPOSE 4480
CMD ["node", "apps/id/dist/index.js"]

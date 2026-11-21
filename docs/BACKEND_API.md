# Backend API

## Health
GET /health

## Signaling
WebSocket /signal

## Turn
GET /credentials -> { username, password, ttl: 3600 }

## Push
POST /push/subscribe
POST /push/send

## Invites
POST /invite
GET /invite/:id

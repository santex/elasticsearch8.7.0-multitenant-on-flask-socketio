<div align="center">
<h1>elasticsearch8.7.0-multitenant-on-flask-socketio</h1>


</div>


```
docker-compose up -d --build
```

This will spin up three containers

## Usage

You can make requests to the containers as follows:

```bash
curl -s -X GET http://foo.localhost | jq
```

This returns:

```json
{
  "status": "ok",
  "statusCode": 200,
  "containerIP": "219.20.128.1",
  "message": "Hello world from container 1"
}
```

Similarly, you can access the second service as follows:

```bash
curl -s -X GET http://bar.localhost | jq
```

This returns:

```json
{
  "status": "ok",
  "statusCode": 200,
  "containerIP": "219.20.128.2",
  "message": "Hello world from container 2"
}
```


## socket io  on 

* browser http://bam.localhost 

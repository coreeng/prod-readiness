## Download dependencies

```
npm install 
```

## Install http-server

```
npm install -g http-server
```

## Render presentation

This expects a mark-down file `report.md` to be present in the top directory.
```
http-server # Run in this folder where index.html exists, follow the link
```

You can then export the rendered content into PDF, by saving the HTML page as PDF.
You can also use `decktape` to export the html page as PDF.

Export to PDF running decktape binary
```
sudo npm install -g decktape
decktape -s 1920x1080 "http://172.16.0.2:8080/?print" report-scan-images-cluster-name.pdf 
```

Export to PDF via a docker container
```
 docker run --rm -t --net=host -v `pwd`:/slides astefanutti/decktape -s 1920x1080 http://localhost:8080\?print slides.pdf 
```

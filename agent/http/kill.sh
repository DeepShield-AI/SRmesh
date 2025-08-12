sudo kill $(ps -a | grep sudo | awk '{print $1}')
sudo kill $(ps -a | grep http_service | awk '{print $1}')
import os

os.chdir('server')
os.system('protoc --python_out=. protobuf.proto')
os.system('python server.py')

import os

os.chdir('client')
os.system('protoc --python_out=. protobuf.proto')
os.system('python client.py')
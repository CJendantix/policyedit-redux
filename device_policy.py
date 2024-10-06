import pathlib

from google.protobuf.json_format import ParseDict
from interfaces.chrome_device_policy_pb2 import ChromeDeviceSettingsProto
from interfaces.device_management_backend_pb2 import PolicyFetchResponse
from interfaces.device_management_backend_pb2 import PolicyData

import signer

#tools for working with the device policy blobs

base_dir = pathlib.Path(__file__).resolve().parent
schema_dir = base_dir / "schema"

class DevicePolicy:
  def __init__(self, policy_bytes):
    self.read_policy(policy_bytes)
    
  #extract device settings from the serialized data
  def read_policy(self, policy_bytes):
    self.fetch_response = PolicyFetchResponse()
    self.fetch_response.ParseFromString(policy_bytes)
    self.policy_data = PolicyData()
    self.policy_data.ParseFromString(self.fetch_response.policy_data)    
    self.device_settings = ChromeDeviceSettingsProto()
    self.device_settings.ParseFromString(self.policy_data.policy_value)

  #serialize the device settings and sign it
  def serialize_policy(self, private_key):
    #place the serialized settings in our protobuf objects
    self.policy_data.policy_value = self.device_settings.SerializeToString()
    self.fetch_response.policy_data = self.policy_data.SerializeToString()

    #sign with rsa and store the public key
    new_signature = signer.rsa_sign(self.fetch_response.policy_data, private_key)
    public_key = signer.get_public_key(private_key)
    self.fetch_response.policy_data_signature = new_signature
    self.fetch_response.new_public_key = public_key
    return self.fetch_response.SerializeToString()


  def import_policy(self, policy_dict):
    ParseDict(policy_dict, self.device_settings)
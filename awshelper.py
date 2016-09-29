import paver.easy
from paver.easy import sh

import json
import os


class Settings:
    def __init__(self, defaults=None):
        self.opts = defaults.copy()
        self.defaults = defaults

    def get(self, key):
        self.load_opts()
        return self.opts[key]

    def set(self, key, val):
        self.opts[key] = val
        self.save_opts()

    def all(self):
        self.load_opts()
        merged = {}
        merged.update(self.defaults)
        merged.update(self.opts)
        return merged

    def delete(self, key):
        if key not in self.opts:
            return
        del self.opts[key]
        self.save_opts()

    def refresh(self):
        self.load_opts()

    def load_opts(self):
        try:
            with open("opts.json", "r") as f:
                self.opts.update(json.load(f))
        except FileNotFoundError:
            # use default opts
            pass

    def save_opts(self):
        with open("opts.json", "w") as f:
            json.dump(self.opts, f, sort_keys=True, indent=4)


class Aws:
    def __init__(self, opts):
        self.opts = opts

    def aws(self, opts, cmd, capture=False, admin_credential=False, save=None, key=None):
        opts.load_opts()
        if not admin_credential:
            os.environ["AWS_ACCESS_KEY_ID"] = self.opts.get("ACCESS_KEY_ID")
            os.environ["AWS_SECRET_ACCESS_KEY"] = self.opts.get("SECRET_ACCESS_KEY")
        elif "AWS_ACCESS_KEY_ID" in os.environ:
            del os.environ["AWS_ACCESS_KEY_ID"] 
            del os.environ["AWS_SECRET_ACCESS_KEY"]
    
        if save:
            output = sh("aws " + cmd.format(**opts.opts), capture=True)
            with open(save, "w") as f:
                f.write(output)
        elif key:
            output = sh("aws --output json " + cmd.format(**opts.opts), capture=True)
            val = json.loads(output)
            for k in key.split("."):
                try:
                    k = int(k)
                except ValueError:
                    # keep it as str
                    pass
                val = val[k]
            print(val)
            return val
        elif capture:
            output = sh("aws --output json " + cmd.format(**opts.opts), capture=True)
            print(output)
            return json.loads(output)
        else:
            sh("aws " + cmd.format(**opts.opts))

    def ec2(self, cmd, *args, **kwargs):
        return self.aws(self.opts, "ec2 " + cmd, *args, **kwargs)

    def ec2_create(self, cmd, id_name=None, key=None):
        val = self.aws(self.opts, "ec2 " + cmd, key=key)
        if id_name:
            print("ec2_create: {0}={1}".format(id_name, val))
            self.opts.set(id_name, val)

    def ec2_create_tags(self, resource_id, name):
        self.ec2_create("create-tags --resources {{{0}}} --tags Key=Name,Value={1}".format(resource_id, name))

    def __call__(self, *args, **kwargs):
        return self.aws(self.opts, *args, **kwargs)

    def ssh(self, cmd, ip_addr):
        keypair_name = self.opts.get("KEY_PAIR_NAME")
        sh('ssh -o StrictHostKeyChecking=no -i ' + keypair_name + '.pem ec2-user@{0} "{1}"'.format(ip_addr, cmd))

    def scp_r2l(self, src, dst, ip_addr):
        keypair_name = self.opts.get("KEY_PAIR_NAME")
        sh("scp -o StrictHostKeyChecking=no -i " + keypair_name + ".pem ec2-user@{0}:{1} {2}".format(ip_addr, src, dst))

    def scp_l2r(self, src, dst, ip_addr):
        keypair_name = self.opts.get("KEY_PAIR_NAME")
        sh("scp -o StrictHostKeyChecking=no -i " + keypair_name + ".pem {0} ec2-user@{1}:{2}".format(src, ip_addr, dst))


class Canned:
    '''
    Utility class (namespace) for regular tasks.
    '''
    
    @staticmethod
    def create_vpc(aws, name):
        # create VPC
        aws.ec2_create("create-vpc --cidr-block 10.0.0.0/16", id_name="VPC_ID", key="Vpc.VpcId")
        aws.ec2_create_tags("VPC_ID", name=name + "Vpc")
    
        # create a subnet within VPC
        aws.ec2_create("create-subnet --vpc-id {VPC_ID} --cidr-block 10.0.1.0/24", id_name="SUBNET_ID", key="Subnet.SubnetId")
    
        # make the subnet public to the internet
        aws.ec2_create("create-internet-gateway", id_name="INTERNET_GATEWAY_ID", key="InternetGateway.InternetGatewayId")
        aws.ec2("attach-internet-gateway --vpc-id {VPC_ID} --internet-gateway-id {INTERNET_GATEWAY_ID}")
        aws.ec2_create("create-route-table --vpc-id {VPC_ID}", id_name="ROUTE_TABLE_ID", key="RouteTable.RouteTableId")
        aws.ec2_create("create-route --route-table-id {ROUTE_TABLE_ID} --destination-cidr-block 0.0.0.0/0 --gateway-id {INTERNET_GATEWAY_ID}")
        aws.ec2_create("associate-route-table --subnet-id {SUBNET_ID} --route-table-id {ROUTE_TABLE_ID}", id_name="ASSOCIATION_ID", key="AssociationId")
        aws.ec2("modify-subnet-attribute --subnet-id {SUBNET_ID} --map-public-ip-on-launch")
    
        # create full-open security group
        aws.ec2_create("create-security-group --group-name " + name + "Open --description " + name + "Open --vpc-id {VPC_ID}", id_name="SECURITY_GROUP_ID", key="GroupId")
        aws.ec2("authorize-security-group-ingress --group-id {SECURITY_GROUP_ID} --protocol all --port 1-65535 --cidr 0.0.0.0/0")
    
    
    @staticmethod
    def delete_vpc(aws):
        aws.ec2("delete-route --route-table-id {ROUTE_TABLE_ID} --destination-cidr-block 0.0.0.0/0")
        aws.ec2("disassociate-route-table --association-id {ASSOCIATION_ID}")
        aws.opts.delete("ASSOCIATION_ID")
        aws.ec2("delete-route-table --route-table-id {ROUTE_TABLE_ID}")
        aws.opts.delete("ROUTE_TABLE_ID")
        aws.ec2("detach-internet-gateway --vpc-id {VPC_ID} --internet-gateway-id {INTERNET_GATEWAY_ID}")
        aws.ec2("delete-internet-gateway --internet-gateway-id {INTERNET_GATEWAY_ID}")
        aws.opts.delete("INTERNET_GATEWAY_ID")
        aws.ec2("delete-subnet --subnet-id {SUBNET_ID}")
        aws.opts.delete("SUBNET_ID")
        aws.ec2("delete-security-group --group-id {SECURITY_GROUP_ID}")
        aws.opts.delete("SECURITY_GROUP_ID")
        aws.ec2("delete-vpc --vpc-id {VPC_ID}")
        aws.opts.delete("VPC_ID")


    @staticmethod
    def prepare_iam(aws):
        aws("iam create-user --user-name {IAM_USERNAME}", admin_credential=True)
        output = aws("iam create-access-key --user-name {IAM_USERNAME}", capture=True, admin_credential=True)
        aws.opts.set("ACCESS_KEY_ID", output["AccessKey"]["AccessKeyId"])
        aws.opts.set("SECRET_ACCESS_KEY", output["AccessKey"]["SecretAccessKey"])
        aws("iam create-group --group-name {IAM_GROUPNAME}", admin_credential=True)
        for policy_arn in aws.opts.get("IAM_POLICIES"):
            aws("iam attach-group-policy --group-name {IAM_GROUPNAME} --policy-arn " + policy_arn, admin_credential=True)
        aws("iam add-user-to-group --group-name {IAM_GROUPNAME} --user-name {IAM_USERNAME}", admin_credential=True)


    @staticmethod
    def destruct_iam(aws):
        aws("iam remove-user-from-group --group-name {IAM_GROUPNAME} --user-name {IAM_USERNAME}", admin_credential=True)
        aws("iam delete-access-key --user-name {IAM_USERNAME} --access-key-id {ACCESS_KEY_ID}", admin_credential=True)
        aws.opts.refresh()
        aws.opts.delete("ACCESS_KEY_ID")
        aws.opts.delete("SECRET_ACCESS_KEY")
        aws("iam delete-user --user-name {IAM_USERNAME}", admin_credential=True)
        aws.opts.delete("IAM_USERNAME")
        for policy_arn in aws.opts.get("IAM_POLICIES"):
            aws("iam detach-group-policy --group-name {IAM_GROUPNAME} --policy-arn " + policy_arn, admin_credential=True)
        aws("iam delete-group --group-name {IAM_GROUPNAME}", admin_credential=True)
        aws.opts.delete("IAM_GROUPNAME")





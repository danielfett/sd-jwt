from sd_jwt.common import SDObj
import yaml
import sys


def load_yaml_specification(file):
    # create new resolver for tags
    resolver = yaml.resolver.Resolver()

    # Define custom YAML tag to indicate selective disclosure
    class SDKeyTag(yaml.YAMLObject):
        yaml_tag = "!sd"

        @classmethod
        def from_yaml(cls, loader, node):
            if isinstance(node, yaml.ScalarNode):
                resolved_type = resolver.resolve(yaml.ScalarNode, node.value, (True, False))
                if resolved_type == "tag:yaml.org,2002:str":
                    mp = loader.construct_yaml_str(node)
                elif resolved_type == "tag:yaml.org,2002:int":
                    mp = loader.construct_yaml_int(node)
                elif resolved_type == "tag:yaml.org,2002:float":
                    mp =  loader.construct_yaml_float(node)
                elif resolved_type == "tag:yaml.org,2002:bool":
                    mp = loader.construct_yaml_bool(node)
                elif resolved_type == "tag:yaml.org,2002:null":
                    mp = None
                else:
                    raise Exception(
                        "Unsupported scalar type for selective disclosure (!sd): {}".format(
                            resolved_type
                        )
                    )
                return SDObj(mp)
            elif isinstance(node, yaml.MappingNode):
                return SDObj(loader.construct_mapping(node))
            elif isinstance(node, yaml.SequenceNode):
                return SDObj(loader.construct_sequence(node))
            else:
                raise Exception(
                    "Unsupported node type for selective disclosure (!sd): {}".format(
                        node
                    )
                )

    with open(file, "r") as f:
        example = yaml.load(f, Loader=yaml.FullLoader)

    for property in ("user_claims", "holder_disclosed_claims"):
        if property not in example:
            sys.exit(f"Specification file must define '{property}'.")

    return example


"""
Takes an object that has been parsed from a YAML file and removes the SDObj wrappers.
"""
def remove_sdobj_wrappers(data):
    if isinstance(data, SDObj):
        return data.value
    elif isinstance(data, dict):
        return {remove_sdobj_wrappers(key): remove_sdobj_wrappers(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [remove_sdobj_wrappers(value) for value in data]
    else:
        return data

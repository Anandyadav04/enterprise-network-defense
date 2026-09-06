import torch
import sys
sys.path.append("/workspace")
from ai.training.model import NetworkTransformerClassifier

print("1. Loading PyTorch model...")
model = NetworkTransformerClassifier(input_dim=14, num_classes=10)
model.load_state_dict(torch.load("/workspace/ai/models/network_classifier_backup.pt", map_location="cpu"))
model.eval()

print("2. Exporting to ONNX...")
dummy_input = torch.zeros(1, 14)
torch.onnx.export(
    model, 
    dummy_input, 
    "/workspace/ai/models/network_classifier.onnx",
    export_params=True,
    opset_version=14,
    do_constant_folding=True,
    input_names=["features"],
    output_names=["probabilities"],
    dynamic_axes={"features": {0: "batch_size"}, "probabilities": {0: "batch_size"}}
)
print("Done! ONNX file successfully created.")

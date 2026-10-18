import copy
import json
import uuid
from pathlib import Path


SOURCE = Path(r"E:\ComfyUI\user\default\workflows\MiniMax_H3_I2V_Official.json")
OUTPUT = Path(r"D:\WorkSpace\rust\meatshell\MiniMax_H3_4图分镜_连续性优化_V2.json")
IMAGE_COUNT = 4
SEGMENT_COUNT = IMAGE_COUNT - 1


def uid():
    return str(uuid.uuid4())


source = json.loads(SOURCE.read_text(encoding="utf-8"))
base_subgraph = source["definitions"]["subgraphs"][0]
base_h3_node = next(node for node in source["nodes"] if node["id"] == 105)
base_load_image = next(node for node in source["nodes"] if node["type"] == "LoadImage")

subgraphs = []
subgraph_ids = []
segment_prompts = [
    """使用 <Picture 1> 作为严格首帧，使用 <Picture 2> 作为严格尾帧。这是同一个中年男性、同一件黑色皮衣、同一座宏大地狱中的连续镜头。画面从正面极近景开始：人物双手挡在脸前持续惨叫，熔火裂纹沿手指、手背、手腕和脖颈缓慢增强。人物双手连续抓向头部，身体因剧痛向右后方失去平衡并沉重倒地。摄影机不得切镜头，从正面近景连续后退、升高并顺时针绕行，最终自然变成高位倾斜俯拍，准确收敛到 <Picture 2> 的倒地姿势、双手位置和构图。动作具有真实重量、惯性和碰撞反馈；镜头速度始终平滑。不要硬切，不要闪白，不要突然换姿势，不要改变人物身份、服装或背景。无字幕、文字、Logo和水印。""",
    """使用 <Picture 1> 作为严格首帧，使用 <Picture 2> 作为严格尾帧。本段必须从上一段倒地动作的余势连续开始，同一个中年男性、同一件黑色皮衣、同一座地狱。人物仰卧在玄武岩上，脸朝上，双手抱住头部，身体仍在抽搐。禁止头部单独旋转，禁止颈部反扭，禁止脸突然转向镜头。起身必须遵循真实人体运动顺序：先屈膝并收紧腹部；然后肩膀、胸腔、骨盆和头部作为一个整体缓慢向人物左侧翻滚；接着左手肘支撑地面，躯干先抬起；头部始终与颈椎和胸腔保持自然对齐，下巴略微内收；直到躯干接近直立后，人物才缓慢抬眼看向镜头。主要视角变化由摄影机完成，而不是由人物扭头完成。摄影机不得切镜头，从高位倾斜俯拍平滑下降并绕到正面三分之四近景，运动速度均匀。人物稳定坐起后，双手才逐渐离开头部并向镜头伸出，一只手更靠近镜头形成自然透视。熔火裂纹连续扩散到面部，双眼逐渐点燃。最终准确收敛到 <Picture 2> 的正面姿势、手部位置和构图。不要脖子旋转超过正常范围，不要头部180度旋转，不要突然回头，不要反向关节，不要身体瞬移，不要换脸或增加肢体。无字幕、文字、Logo和水印。""",
    """使用 <Picture 1> 作为严格首帧，使用 <Picture 2> 作为严格尾帧。本段必须延续上一段双手前伸和惨叫的动作余势，同一个人物、同一件黑色皮衣、同一座地狱。人物仰头发出最后一次痛苦嘶吼，火焰从发根连续燃起；皮肤在烟雾、火星和热浪中超自然地渐进消散，逐步显露结构正确的额骨、眼窝、颧骨、鼻腔、上下颌和牙齿。无血、无肌肉和内脏。摄影机不得切镜头，从正面三分之四近景连续向人物左侧平滑绕行并略微降低；人物双手自然落下，身体沉重前倾，缓慢低下燃烧的骷髅头。最终准确收敛到 <Picture 2> 的侧面低头构图、完整骷髅、火焰轮廓、皮衣和背景。不要瞬间换头、漂浮头骨、颈部断开或突然改变姿势。无字幕、文字、Logo和水印。""",
]
for segment in range(1, SEGMENT_COUNT + 1):
    graph = copy.deepcopy(base_subgraph)
    graph_id = uid()
    graph["id"] = graph_id
    graph["name"] = f"MiniMax H3 分镜 {segment}（首尾帧）"

    # The stock H3 graph returns a VIDEO. For a multi-shot master timeline we
    # expose decoded frames instead and mux once after all five segments.
    graph["nodes"] = [n for n in graph["nodes"] if n["id"] not in {23, 24, 91}]
    graph["links"] = [
        link for link in graph["links"]
        if link["origin_id"] not in {23, 24, 91}
        and link["target_id"] not in {23, 24, 91}
        and link["target_id"] != -20
    ]
    output_link_id = max(link["id"] for link in graph["links"]) + 1
    graph["links"].append({
        "id": output_link_id,
        "origin_id": 10,
        "origin_slot": 0,
        "target_id": -20,
        "target_slot": 0,
        "type": "IMAGE",
    })
    graph["outputs"] = [{
        "id": uid(),
        "name": "IMAGE",
        "type": "IMAGE",
        "linkIds": [output_link_id],
        "localized_name": "视频帧",
        "pos": [714, 4834],
    }]
    subgraphs.append(graph)
    subgraph_ids.append(graph_id)

nodes = []
links = []
next_link = 1


def add_link(origin, origin_slot, target, target_slot, link_type):
    global next_link
    link_id = next_link
    next_link += 1
    links.append([link_id, origin, origin_slot, target, target_slot, link_type])
    return link_id


# Storyboard keyframes.
image_ids = []
for index in range(IMAGE_COUNT):
    node = copy.deepcopy(base_load_image)
    node_id = index + 1
    image_ids.append(node_id)
    node["id"] = node_id
    node["title"] = f"分镜 {index + 1}"
    node["pos"] = [-1700, -150 + index * 300]
    node["size"] = [330, 260]
    node["order"] = index
    node["mode"] = 0
    node["widgets_values"] = [f"{index + 1}.png", "image"]
    node["outputs"][0]["links"] = []
    nodes.append(node)

# H3 first/last-frame segments.
segment_ids = []
for index in range(SEGMENT_COUNT):
    node = copy.deepcopy(base_h3_node)
    node_id = 20 + index
    segment_ids.append(node_id)
    node["id"] = node_id
    node["type"] = subgraph_ids[index]
    node["title"] = f"MiniMax H3 分镜 {index + 1}：图{index + 1} → 图{index + 2}"
    node["pos"] = [-1050, -100 + index * 330]
    node["size"] = [500, 300]
    node["order"] = 10 + index
    node["mode"] = 0
    node["inputs"] = copy.deepcopy(base_h3_node["inputs"])
    for inp in node["inputs"]:
        inp["link"] = None
    first_link = add_link(image_ids[index], 0, node_id, 0, "IMAGE")
    last_link = add_link(image_ids[index + 1], 0, node_id, 1, "IMAGE")
    node["inputs"][0]["link"] = first_link
    node["inputs"][1]["link"] = last_link
    nodes[image_ids[index] - 1]["outputs"][0]["links"].append(first_link)
    nodes[image_ids[index + 1] - 1]["outputs"][0]["links"].append(last_link)
    node["outputs"] = [{
        "localized_name": "视频帧",
        "name": "IMAGE",
        "type": "IMAGE",
        "links": [],
    }]
    durations = [3.5, 6.0, 5.0]
    node["widgets_values"] = [
        segment_prompts[index],
        864,
        480,
        durations[index],
        100000 + index,
        "minimax_h3_fl2va_pruned_int8_convrot.safetensors",
        "qwen3vl_32b_minimax_h3_nvfp4_awq.safetensors",
        "minimax_h3_video_vae_fp16.safetensors",
        "minimax_h3_audio_vae_fp32.safetensors",
    ]
    nodes.append(node)

# Concatenate decoded frame sequences.
current_node = segment_ids[0]
for index in range(1, SEGMENT_COUNT):
    # The final frame of the previous segment is identical to the first frame
    # of the next segment. Drop that duplicate to avoid a visible one-frame hold.
    trim_id = 30 + index
    trim_link = add_link(segment_ids[index], 0, trim_id, 0, "IMAGE")
    next(n for n in nodes if n["id"] == segment_ids[index])["outputs"][0]["links"].append(trim_link)
    nodes.append({
        "id": trim_id,
        "type": "ImageFromBatch",
        "title": f"删除分镜 {index + 1} 开头重复帧",
        "pos": [-500, 50 + index * 300],
        "size": [280, 130],
        "flags": {},
        "order": 18 + index,
        "mode": 0,
        "inputs": [
            {"name": "image", "type": "IMAGE", "link": trim_link},
            {"name": "batch_index", "type": "INT", "widget": {"name": "batch_index"}, "link": None},
            {"name": "length", "type": "INT", "widget": {"name": "length"}, "link": None},
        ],
        "outputs": [{"name": "IMAGE", "type": "IMAGE", "links": []}],
        "properties": {"Node name for S&R": "ImageFromBatch"},
        "widgets_values": [1, 4096],
    })
    batch_id = 40 + index
    first = add_link(current_node, 0, batch_id, 0, "IMAGE")
    second = add_link(trim_id, 0, batch_id, 1, "IMAGE")
    next(n for n in nodes if n["id"] == current_node)["outputs"][0]["links"].append(first)
    next(n for n in nodes if n["id"] == trim_id)["outputs"][0]["links"].append(second)
    batch = {
        "id": batch_id,
        "type": "ImageBatch",
        "pos": [-350, -20 + index * 260],
        "size": [270, 110],
        "flags": {},
        "order": 20 + index,
        "mode": 0,
        "inputs": [
            {"name": "image1", "type": "IMAGE", "link": first},
            {"name": "image2", "type": "IMAGE", "link": second},
        ],
        "outputs": [{"name": "IMAGE", "type": "IMAGE", "links": []}],
        "properties": {"Node name for S&R": "ImageBatch"},
        "widgets_values": [],
    }
    nodes.append(batch)
    current_node = batch_id

create_id = 60
save_id = 61
frames_link = add_link(current_node, 0, create_id, 0, "IMAGE")
video_link = add_link(create_id, 0, save_id, 0, "VIDEO")
next(n for n in nodes if n["id"] == current_node)["outputs"][0]["links"].append(frames_link)
nodes.append({
    "id": create_id,
    "type": "CreateVideo",
    "pos": [100, 850],
    "size": [280, 110],
    "flags": {},
    "order": 30,
    "mode": 0,
    "inputs": [
        {"name": "images", "type": "IMAGE", "link": frames_link},
        {"name": "audio", "shape": 7, "type": "AUDIO", "link": None},
        {"name": "fps", "type": "FLOAT", "widget": {"name": "fps"}, "link": None},
    ],
    "outputs": [{"name": "VIDEO", "type": "VIDEO", "links": [video_link]}],
    "properties": {"Node name for S&R": "CreateVideo"},
    "widgets_values": [24],
})
nodes.append({
    "id": save_id,
    "type": "SaveVideo",
    "pos": [450, 760],
    "size": [520, 400],
    "flags": {},
    "order": 31,
    "mode": 0,
    "inputs": [
        {"name": "video", "type": "VIDEO", "link": video_link},
        {"name": "filename_prefix", "type": "STRING", "widget": {"name": "filename_prefix"}, "link": None},
        {"name": "format", "type": "COMBO", "widget": {"name": "format"}, "link": None},
        {"name": "codec", "type": "COMBO", "widget": {"name": "codec"}, "link": None},
    ],
    "outputs": [],
    "properties": {"Node name for S&R": "SaveVideo"},
    "widgets_values": ["video/MiniMax_H3_4图分镜_连续性优化_V2", "auto", "auto"],
})

workflow = {
    "id": uid(),
    "revision": 0,
    "last_node_id": save_id,
    "last_link_id": next_link - 1,
    "nodes": nodes,
    "links": links,
    "groups": [
        {"id": 1, "title": "1. 四张分镜图（相邻图片组成一段）", "bounding": [-1760, -220, 450, 1300], "color": "#3f789e", "flags": {}},
        {"id": 2, "title": "2. 三段 MiniMax H3 首尾帧生成", "bounding": [-1120, -220, 650, 1300], "color": "#3f789e", "flags": {}},
        {"id": 3, "title": "3. 合并并保存约15秒视频", "bounding": [-420, -80, 1450, 1000], "color": "#3f789e", "flags": {}},
    ],
    "definitions": {"subgraphs": subgraphs},
    "config": {},
    "extra": copy.deepcopy(source.get("extra", {})),
    "version": 0.4,
}

# Structural validation.
node_by_id = {node["id"]: node for node in nodes}
for link in links:
    assert link[1] in node_by_id and link[3] in node_by_id
for graph in subgraphs:
    assert len(graph["outputs"]) == 1 and graph["outputs"][0]["type"] == "IMAGE"

OUTPUT.write_text(json.dumps(workflow, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
print(OUTPUT)
print(f"nodes={len(nodes)} links={len(links)} subgraphs={len(subgraphs)}")

package nodes

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"wx_channel/pkg/flowengine/engine"
)

type DownloadNode struct {
	Id     string
	Config map[string]interface{}
}

// download --url "https://media.example.invalid/video.mp4" --key 123456 --filename "example.mp4"
func NewDownloadNode(config map[string]interface{}) engine.Node {
	id, _ := config["id"].(string)
	return &DownloadNode{Id: id, Config: config}
}

func (n *DownloadNode) ID() string   { return n.Id }
func (n *DownloadNode) Type() string { return "DownloadNode" }

func (n *DownloadNode) Execute(ctx *engine.ProcessContext) (bool, []string, error) {
	urlVal, _ := ctx.Data["url"].(string)
	if urlVal == "" {
		return false, nil, errors.New("missing download_url")
	}
	filenameVal, _ := ctx.Data["filename"].(string)
	if filenameVal == "" {
		return false, nil, errors.New("missing filename")
	}
	outDir := "downloads"
	if v, ok := n.Config["output_dir"].(string); ok && v != "" {
		outDir = v
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return false, nil, err
	}
	// filename := deriveFilename(urlVal)
	fullpath := filepath.Join(outDir, filenameVal)
	if err := httpDownload(urlVal, fullpath); err != nil {
		return false, nil, err
	}
	ctx.Data["local_path"] = fullpath
	next := ctx.EngineRef.GetNextNodeIDsFromDefinition(ctx, n.Id)
	fmt.Println("next nodes", next)
	return true, next, nil
}

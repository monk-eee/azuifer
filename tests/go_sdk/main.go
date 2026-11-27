// Runs the Go Azure Storage SDKs against Azuifer. Start the server with
// --services blob,queue,table,file,dfs --hns-accounts devstoreaccount1.
// Use an IP address as the host: the Go SDKs read any other host name as host-style
// and misread the account in a path-style URL as the container.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/data/aztables"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/lease"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/sas"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azdatalake"
	dlfile "github.com/Azure/azure-sdk-for-go/sdk/storage/azdatalake/file"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azdatalake/filesystem"
	dlservice "github.com/Azure/azure-sdk-for-go/sdk/storage/azdatalake/service"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azfile/service"
	sharepkg "github.com/Azure/azure-sdk-for-go/sdk/storage/azfile/share"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azqueue"
)

const account = "devstoreaccount1"

var failures = 0
var only string

func step(name string, fn func() error) {
	if only != "" && !strings.HasPrefix(name, only) {
		return
	}
	if err := fn(); err != nil {
		failures++
		msg := strings.Join(strings.Fields(err.Error()), " ")
		if len(msg) > 400 {
			msg = msg[:400]
		}
		fmt.Println("FAIL " + name + ": " + msg)
		return
	}
	fmt.Println("PASS " + name)
}

func check(ok bool, what string) error {
	if !ok {
		return fmt.Errorf("check failed: %s", what)
	}
	return nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func random(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func main() {
	if len(os.Args) > 1 {
		only = os.Args[1]
	}
	host := os.Getenv("AZUIFER_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	key := envOr("AZUIFER_ACCOUNT_KEY", "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==")
	ctx := context.Background()
	sfx := fmt.Sprintf("%x", random(4))

	// ---- Blob
	cred, err := azblob.NewSharedKeyCredential(account, key)
	if err != nil {
		panic(err)
	}
	bc, err := azblob.NewClientWithSharedKeyCredential(fmt.Sprintf("http://%s:10000/%s", host, account), cred, nil)
	if err != nil {
		panic(err)
	}
	container := "go" + sfx
	step("blob: create container with metadata", func() error {
		_, err := bc.CreateContainer(ctx, container, &azblob.CreateContainerOptions{Metadata: map[string]*string{"k": to.Ptr("v")}})
		return err
	})
	step("blob: upload, download and ranged download", func() error {
		data := random(5000)
		if _, err := bc.UploadBuffer(ctx, container, "small.bin", data, nil); err != nil {
			return err
		}
		buf := make([]byte, len(data))
		if _, err := bc.DownloadBuffer(ctx, container, "small.bin", buf, nil); err != nil {
			return err
		}
		if err := check(bytes.Equal(buf, data), "bytes"); err != nil {
			return err
		}
		part := make([]byte, 200)
		if _, err := bc.DownloadBuffer(ctx, container, "small.bin", part, &azblob.DownloadBufferOptions{Range: blob.HTTPRange{Offset: 100, Count: 200}}); err != nil {
			return err
		}
		return check(bytes.Equal(part, data[100:300]), "range")
	})
	step("blob: parallel chunked upload 20 MiB", func() error {
		data := random(20 * 1024 * 1024)
		if _, err := bc.UploadBuffer(ctx, container, "big.bin", data, &azblob.UploadBufferOptions{BlockSize: 4 * 1024 * 1024, Concurrency: 4}); err != nil {
			return err
		}
		buf := make([]byte, len(data))
		if _, err := bc.DownloadBuffer(ctx, container, "big.bin", buf, &azblob.DownloadBufferOptions{BlockSize: 4 * 1024 * 1024, Concurrency: 4}); err != nil {
			return err
		}
		return check(bytes.Equal(buf, data), "bytes")
	})
	step("blob: list flat and hierarchical", func() error {
		if _, err := bc.UploadBuffer(ctx, container, "dir/a.txt", []byte("a"), nil); err != nil {
			return err
		}
		pager := bc.NewListBlobsFlatPager(container, nil)
		found := false
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return err
			}
			for _, item := range page.Segment.BlobItems {
				if *item.Name == "dir/a.txt" {
					found = true
				}
			}
		}
		if err := check(found, "flat"); err != nil {
			return err
		}
		cc := bc.ServiceClient().NewContainerClient(container)
		hp := cc.NewListBlobsHierarchyPager("/", nil)
		prefix := false
		for hp.More() {
			page, err := hp.NextPage(ctx)
			if err != nil {
				return err
			}
			for _, p := range page.Segment.BlobPrefixes {
				if *p.Name == "dir/" {
					prefix = true
				}
			}
		}
		return check(prefix, "hierarchy")
	})
	step("blob: metadata, headers, snapshot, lease, tags", func() error {
		b := bc.ServiceClient().NewContainerClient(container).NewBlockBlobClient("small.bin")
		if _, err := b.SetMetadata(ctx, map[string]*string{"x": to.Ptr("1")}, nil); err != nil {
			return err
		}
		if _, err := b.SetHTTPHeaders(ctx, blob.HTTPHeaders{BlobContentType: to.Ptr("text/x-test")}, nil); err != nil {
			return err
		}
		props, err := b.GetProperties(ctx, nil)
		if err != nil {
			return err
		}
		if err := check(*props.ContentType == "text/x-test" && len(props.Metadata) == 1, "props"); err != nil {
			return err
		}
		if _, err := b.CreateSnapshot(ctx, nil); err != nil {
			return err
		}
		lc, err := lease.NewBlobClient(b, nil)
		if err != nil {
			return err
		}
		if _, err := lc.AcquireLease(ctx, 30, nil); err != nil {
			return err
		}
		if _, err := lc.RenewLease(ctx, nil); err != nil {
			return err
		}
		if _, err := lc.ReleaseLease(ctx, nil); err != nil {
			return err
		}
		if _, err := b.SetTags(ctx, map[string]string{"color": "blue"}, nil); err != nil {
			return err
		}
		tags, err := b.GetTags(ctx, nil)
		if err != nil {
			return err
		}
		return check(len(tags.BlobTagSet) == 1, "tags")
	})
	step("blob: SAS and server-side copy", func() error {
		b := bc.ServiceClient().NewContainerClient(container).NewBlockBlobClient("small.bin")
		url, err := b.GetSASURL(sas.BlobPermissions{Read: true}, time.Now().Add(time.Hour), nil)
		if err != nil {
			return err
		}
		dst := bc.ServiceClient().NewContainerClient(container).NewBlockBlobClient("copy.bin")
		if _, err := dst.StartCopyFromURL(ctx, url, nil); err != nil {
			return err
		}
		props, err := dst.GetProperties(ctx, nil)
		if err != nil {
			return err
		}
		return check(*props.ContentLength == 5000, "copy length")
	})
	step("blob: delete container", func() error {
		_, err := bc.DeleteContainer(ctx, container, nil)
		return err
	})

	// ---- Queue
	step("queue: lifecycle", func() error {
		qkey, err := azqueue.NewSharedKeyCredential(account, key)
		if err != nil {
			return err
		}
		qs, err := azqueue.NewServiceClientWithSharedKeyCredential(fmt.Sprintf("http://%s:10001/%s", host, account), qkey, nil)
		if err != nil {
			return err
		}
		q := qs.NewQueueClient("goq" + sfx)
		if _, err := q.Create(ctx, nil); err != nil {
			return err
		}
		if _, err := q.EnqueueMessage(ctx, "one", nil); err != nil {
			return err
		}
		if _, err := q.EnqueueMessage(ctx, "two", nil); err != nil {
			return err
		}
		peek, err := q.PeekMessages(ctx, &azqueue.PeekMessagesOptions{NumberOfMessages: to.Ptr(int32(2))})
		if err != nil {
			return err
		}
		if err := check(len(peek.Messages) == 2, "peek"); err != nil {
			return err
		}
		got, err := q.DequeueMessage(ctx, nil)
		if err != nil {
			return err
		}
		if err := check(len(got.Messages) == 1 && *got.Messages[0].MessageText == "one", "dequeue"); err != nil {
			return err
		}
		id, initial := *got.Messages[0].MessageID, *got.Messages[0].PopReceipt
		updated, err := q.UpdateMessage(ctx, id, initial, "uno", &azqueue.UpdateMessageOptions{VisibilityTimeout: to.Ptr(int32(60))})
		if err != nil {
			return err
		}
		if err := check(updated.PopReceipt != nil && *updated.PopReceipt != initial, "update rotates the receipt"); err != nil {
			return err
		}
		if _, err := q.DeleteMessage(ctx, id, initial, nil); err == nil {
			return fmt.Errorf("stale receipt deleted a message")
		} else {
			var response *azcore.ResponseError
			if !errors.As(err, &response) || response.StatusCode != 404 || response.ErrorCode != "MessageNotFound" {
				return fmt.Errorf("stale receipt: %w", err)
			}
		}
		hidden, err := q.PeekMessages(ctx, &azqueue.PeekMessagesOptions{NumberOfMessages: to.Ptr(int32(2))})
		if err != nil {
			return err
		}
		if err := check(len(hidden.Messages) == 1 && *hidden.Messages[0].MessageText == "two", "updated message is hidden"); err != nil {
			return err
		}
		visible, err := q.UpdateMessage(ctx, id, *updated.PopReceipt, "uno", &azqueue.UpdateMessageOptions{VisibilityTimeout: to.Ptr(int32(0))})
		if err != nil {
			return err
		}
		peek, err = q.PeekMessages(ctx, &azqueue.PeekMessagesOptions{NumberOfMessages: to.Ptr(int32(2))})
		if err != nil {
			return err
		}
		found := false
		for _, message := range peek.Messages {
			found = found || (*message.MessageID == id && *message.MessageText == "uno")
		}
		if err := check(found && visible.PopReceipt != nil, "updated message becomes visible"); err != nil {
			return err
		}
		if _, err := q.DeleteMessage(ctx, id, *visible.PopReceipt, nil); err != nil {
			return err
		}
		_, err = q.Delete(ctx, nil)
		return err
	})

	// ---- Table
	step("table: crud, query, transaction", func() error {
		tcred, err := aztables.NewSharedKeyCredential(account, key)
		if err != nil {
			return err
		}
		ts, err := aztables.NewServiceClientWithSharedKey(fmt.Sprintf("http://%s:10002/%s", host, account), tcred, nil)
		if err != nil {
			return err
		}
		name := "got" + sfx
		if _, err := ts.CreateTable(ctx, name, nil); err != nil {
			return err
		}
		tc := ts.NewClient(name)
		entity := []byte(`{"PartitionKey":"p","RowKey":"r1","n":1,"s":"alpha"}`)
		if _, err := tc.AddEntity(ctx, entity, nil); err != nil {
			return err
		}
		resp, err := tc.GetEntity(ctx, "p", "r1", nil)
		if err != nil {
			return err
		}
		if err := check(strings.Contains(string(resp.Value), "alpha"), "get"); err != nil {
			return err
		}
		filter := "PartitionKey eq 'p'"
		pager := tc.NewListEntitiesPager(&aztables.ListEntitiesOptions{Filter: &filter})
		count := 0
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return err
			}
			count += len(page.Entities)
		}
		if err := check(count == 1, "query"); err != nil {
			return err
		}
		actions := []aztables.TransactionAction{
			{ActionType: aztables.TransactionTypeAdd, Entity: []byte(`{"PartitionKey":"b","RowKey":"1","v":1}`)},
			{ActionType: aztables.TransactionTypeAdd, Entity: []byte(`{"PartitionKey":"b","RowKey":"2","v":2}`)},
		}
		if _, err := tc.SubmitTransaction(ctx, actions, nil); err != nil {
			return err
		}
		_, err = ts.DeleteTable(ctx, name, nil)
		return err
	})

	// ---- Files
	step("files: share, directory, file", func() error {
		fkey, err := service.NewSharedKeyCredential(account, key)
		if err != nil {
			return err
		}
		fs, err := service.NewClientWithSharedKeyCredential(fmt.Sprintf("http://%s:10004/%s", host, account), fkey, nil)
		if err != nil {
			return err
		}
		share := fs.NewShareClient("gos" + sfx)
		if _, err := share.Create(ctx, nil); err != nil {
			return err
		}
		dir := share.NewDirectoryClient("d1")
		if _, err := dir.Create(ctx, nil); err != nil {
			return err
		}
		f := dir.NewFileClient("f.bin")
		data := random(300000)
		if _, err := f.Create(ctx, int64(len(data)), nil); err != nil {
			return err
		}
		if err := f.UploadBuffer(ctx, data, nil); err != nil {
			return err
		}
		buf := make([]byte, len(data))
		if _, err := f.DownloadBuffer(ctx, buf, nil); err != nil {
			return err
		}
		if err := check(bytes.Equal(buf, data), "bytes"); err != nil {
			return err
		}
		_, err = share.Delete(ctx, nil)
		return err
	})

	step("files: NFS share, hard link, symbolic link", func() error {
		fkey, err := service.NewSharedKeyCredential(account, key)
		if err != nil {
			return err
		}
		fs, err := service.NewClientWithSharedKeyCredential(fmt.Sprintf("http://%s:10004/%s", host, account), fkey, nil)
		if err != nil {
			return err
		}
		nfs := fs.NewShareClient("gon" + sfx)
		if _, err := nfs.Create(ctx, &sharepkg.CreateOptions{EnabledProtocols: to.Ptr("NFS")}); err != nil {
			return err
		}
		root := nfs.NewRootDirectoryClient()
		target := root.NewFileClient("target.bin")
		data := random(5000)
		if _, err := target.Create(ctx, int64(len(data)), nil); err != nil {
			return err
		}
		if err := target.UploadBuffer(ctx, data, nil); err != nil {
			return err
		}
		hard := root.NewFileClient("hard.bin")
		if _, err := hard.CreateHardLink(ctx, "target.bin", nil); err != nil {
			return err
		}
		buf := make([]byte, len(data))
		if _, err := hard.DownloadBuffer(ctx, buf, nil); err != nil {
			return err
		}
		if err := check(bytes.Equal(buf, data), "hard link shares the bytes"); err != nil {
			return err
		}
		sym := root.NewFileClient("sym.bin")
		if _, err := sym.CreateSymbolicLink(ctx, "target.bin", nil); err != nil {
			return err
		}
		got, err := sym.GetSymbolicLink(ctx, nil)
		if err != nil {
			return err
		}
		if err := check(got.LinkText != nil && *got.LinkText == "target.bin", "link text"); err != nil {
			return err
		}
		_, err = nfs.Delete(ctx, nil)
		return err
	})

	// ---- DFS
	step("dfs: filesystem, directory, file, rename", func() error {
		dcred, err := azdatalake.NewSharedKeyCredential(account, key)
		if err != nil {
			return err
		}
		ds, err := dlservice.NewClientWithSharedKeyCredential(fmt.Sprintf("http://%s:%s/%s", host, envOr("AZUIFER_DFS_PORT", "10003"), account), dcred, nil)
		if err != nil {
			return err
		}
		name := "gof" + sfx
		fsc := ds.NewFileSystemClient(name)
		if _, err := fsc.Create(ctx, nil); err != nil {
			return err
		}
		dir := fsc.NewDirectoryClient("dir1")
		if _, err := dir.Create(ctx, nil); err != nil {
			return err
		}
		f := fsc.NewFileClient("dir1/hello.txt")
		if _, err := f.Create(ctx, nil); err != nil {
			return err
		}
		if err := f.UploadBuffer(ctx, []byte("hello dfs"), nil); err != nil {
			return err
		}
		resp, err := f.DownloadStream(ctx, nil)
		if err != nil {
			return err
		}
		body, _ := io.ReadAll(resp.Body)
		if err := check(string(body) == "hello dfs", "read "+string(body)); err != nil {
			return err
		}
		if _, err := f.Rename(ctx, "dir1/renamed.txt", nil); err != nil {
			return err
		}
		pager := fsc.NewListPathsPager(true, &filesystem.ListPathsOptions{})
		names := []string{}
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return err
			}
			for _, p := range page.Paths {
				names = append(names, *p.Name)
			}
		}
		if err := check(strings.Contains(strings.Join(names, ","), "dir1/renamed.txt"), strings.Join(names, ",")); err != nil {
			return err
		}
		_, err = fsc.Delete(ctx, nil)
		return err
	})

	step("dfs: create with an expiry", func() error {
		dcred, err := azdatalake.NewSharedKeyCredential(account, key)
		if err != nil {
			return err
		}
		ds, err := dlservice.NewClientWithSharedKeyCredential(fmt.Sprintf("http://%s:%s/%s", host, envOr("AZUIFER_DFS_PORT", "10003"), account), dcred, nil)
		if err != nil {
			return err
		}
		fsc := ds.NewFileSystemClient("goe" + sfx)
		if _, err := fsc.Create(ctx, nil); err != nil {
			return err
		}
		f := fsc.NewFileClient("ttl.txt")
		opts := &dlfile.CreateOptions{Expiry: dlfile.CreateExpiryValues{ExpiryType: dlfile.CreateExpiryTypeRelativeToNow, ExpiresOn: "4000"}}
		if _, err := f.Create(ctx, opts); err != nil {
			return err
		}
		if err := f.UploadBuffer(ctx, []byte("short lived"), nil); err != nil {
			return err
		}
		if _, err := f.GetProperties(ctx, nil); err != nil {
			return fmt.Errorf("present before the deadline: %w", err)
		}
		time.Sleep(5 * time.Second)
		if _, err := f.GetProperties(ctx, nil); err == nil {
			return fmt.Errorf("the file outlived its deadline")
		}
		_, err = fsc.Delete(ctx, nil)
		return err
	})

	if failures == 0 {
		fmt.Println("ALL PASSED")
	} else {
		fmt.Printf("%d FAILED\n", failures)
		os.Exit(1)
	}
}

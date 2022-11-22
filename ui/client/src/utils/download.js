// 下载
export const binaryDownload = (data, file) => {

        let blob = new Blob([data], {
            type: [
                'image/gif',
                'image/jpeg',
                'image/png',
                'image/JPG',
                'image/JPEG',
                'image/GIF',
                'image/PNG',
                'video/mp4',
                'video/rmvb',
                'video/avi',
                'audio/mpeg',
                'audio/mp3',
                'application/pdf',
                'application/word',
                'application/msword',
                'application/ppt',
                'application/vnd.ms-powerpoint',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'application/vnd.openxmlformats-officedocument.presentationml.presentation',
                'application/vnd.ms-excel',
                'application/vnd.ms-xlsx',
                'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            ]
        })

        if (window.navigator && window.navigator.msSaveOrOpenBlob) {
            window.navigator.msSaveOrOpenBlob(blob, file.name);
        }
        // for Non-IE (chrome, firefox etc.)
        else {
            let aurl = window.URL.createObjectURL(blob)
            let link = document.createElement('a')
            link.style.opacity = '0'
            link.href = aurl
            link.setAttribute('download', file.name)
            let body = document.body
            body.appendChild(link)
            link.click()
            link.remove()
        }
    }
    // 预览
export const previewDownload = (data, file) => {
    var url = 'data:image/png;base64,' + btoa(new Uint8Array(data).reduce((data, key) => data + String.fromCharCode(key), ''))
    return url

}
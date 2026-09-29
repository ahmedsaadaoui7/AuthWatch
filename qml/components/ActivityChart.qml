import QtQuick

Item {
    id: root
    property var points: []
    BrandTheme { id: theme }

    function pointCount() { return points ? points.length : 0 }
    function countAt(index) {
        if (!points || index < 0 || index >= points.length) return 0
        return Number(points[index].count || 0)
    }

    Canvas {
        id: canvas
        anchors.fill: parent
        visible: root.pointCount() > 0

        onPaint: {
            var ctx = getContext("2d")
            ctx.clearRect(0, 0, width, height)
            var left = 46
            var right = width - 18
            var top = 18
            var bottom = height - 28
            var usableWidth = right - left
            var usableHeight = bottom - top
            var maxValue = 1
            for (var i = 0; i < root.points.length; i++) maxValue = Math.max(maxValue, root.countAt(i))

            ctx.lineWidth = 1
            ctx.strokeStyle = "#173247"
            ctx.setLineDash([3, 5])
            for (var g = 0; g <= 4; g++) {
                var gy = top + (usableHeight * g / 4)
                ctx.beginPath(); ctx.moveTo(left, gy); ctx.lineTo(right, gy); ctx.stroke()
            }
            ctx.setLineDash([])

            var step = root.points.length > 1 ? usableWidth / (root.points.length - 1) : 0
            var coords = []
            for (var p = 0; p < root.points.length; p++) {
                var x = left + step * p
                var y = bottom - ((root.countAt(p) / maxValue) * usableHeight)
                coords.push({x: x, y: y})
            }

            if (coords.length > 0) {
                var gradient = ctx.createLinearGradient(0, top, 0, bottom)
                gradient.addColorStop(0, "rgba(36,214,231,0.22)")
                gradient.addColorStop(1, "rgba(36,214,231,0.01)")
                ctx.beginPath(); ctx.moveTo(coords[0].x, bottom)
                for (var a = 0; a < coords.length; a++) ctx.lineTo(coords[a].x, coords[a].y)
                ctx.lineTo(coords[coords.length - 1].x, bottom); ctx.closePath(); ctx.fillStyle = gradient; ctx.fill()

                ctx.beginPath(); ctx.lineWidth = 2.5; ctx.strokeStyle = "#24D6E7"; ctx.shadowColor = "#24D6E7"; ctx.shadowBlur = 6
                ctx.moveTo(coords[0].x, coords[0].y)
                for (var b = 1; b < coords.length; b++) ctx.lineTo(coords[b].x, coords[b].y)
                ctx.stroke(); ctx.shadowBlur = 0

                ctx.fillStyle = "#63F0F7"
                for (var c = 0; c < coords.length; c++) { ctx.beginPath(); ctx.arc(coords[c].x, coords[c].y, 3.2, 0, Math.PI * 2); ctx.fill() }
            }
        }

        Connections { target: root; function onPointsChanged() { canvas.requestPaint() } }
        onWidthChanged: requestPaint()
        onHeightChanged: requestPaint()
    }

    EmptyState {
        anchors.fill: parent
        visible: root.pointCount() === 0
        title: "No finding activity yet"
        message: "Analyze telemetry to populate the activity timeline."
        code: "TL"
    }
}

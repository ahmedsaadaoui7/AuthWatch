import QtQuick

Item {
    id: root
    property var points: []
    BrandTheme { id: theme }
    function pointCount() { return points ? points.length : 0 }

    Canvas {
        id: canvas
        anchors.fill: parent
        visible: root.pointCount() > 0
        onPaint: {
            var ctx = getContext("2d"); ctx.clearRect(0,0,width,height)
            var left=20, right=width-16, top=16, bottom=height-28
            ctx.strokeStyle="#173247"; ctx.lineWidth=1; ctx.beginPath(); ctx.moveTo(left,bottom); ctx.lineTo(right,bottom); ctx.stroke()
            if (!root.points || root.points.length===0) return
            var maxValue=1; for (var i=0;i<root.points.length;i++) maxValue=Math.max(maxValue, Number(root.points[i].count || 0))
            var usableWidth=right-left, usableHeight=bottom-top, step=root.points.length>1?usableWidth/(root.points.length-1):0
            ctx.strokeStyle="#24D6E7"; ctx.lineWidth=2.5; ctx.shadowColor="#24D6E7"; ctx.shadowBlur=5; ctx.beginPath()
            for (var j=0;j<root.points.length;j++) { var x=left+step*j; var y=bottom-((Number(root.points[j].count||0)/maxValue)*usableHeight); if(j===0)ctx.moveTo(x,y);else ctx.lineTo(x,y) }
            ctx.stroke(); ctx.shadowBlur=0
        }
        Connections { target: root; function onPointsChanged(){canvas.requestPaint()} }
        onWidthChanged: requestPaint(); onHeightChanged: requestPaint()
    }

    EmptyState { anchors.fill: parent; visible: root.pointCount()===0; title: "Timeline not available yet"; message: "Investigation events will appear here after analysis."; code: "EV" }
}

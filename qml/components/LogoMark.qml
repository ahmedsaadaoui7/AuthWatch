import QtQuick

Item {
    id: root
    property int preferredSize: 44
    width: preferredSize
    height: preferredSize

    Image {
        anchors.fill: parent
        source: "../assets/authwatch-mark.svg"
        fillMode: Image.PreserveAspectFit
        smooth: true
        mipmap: true
    }
}

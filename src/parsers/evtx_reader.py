from pathlib import Path

from Evtx.Evtx import Evtx


def iter_evtx_xml_records(file_path):
    file_path = Path(file_path)

    if not file_path.is_file():
        raise FileNotFoundError(f"EVTX file not found: {file_path}")

    with Evtx(str(file_path)) as evtx_file:
        for record in evtx_file.records():
            yield record.xml()

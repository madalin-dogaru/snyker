def read_project_ids_from_file(file_path):
    with open(file_path, "r") as file:
        project_ids = [line.strip() for line in file.readlines()]
    return project_ids

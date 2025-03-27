from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from .models import Folder, Portfolio, UserProfile
from .forms import FolderForm, DocumentForm

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from .models import Folder, Portfolio, UserProfile
from .forms import FolderForm, DocumentForm



from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from .forms import FolderForm, DocumentForm

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from .models import Folder
from .forms import FolderForm, DocumentForm

from .models import Document as MyDocument



def upload_document(request):
    if request.method == "POST":
        form = DocumentForm(request.POST, request.FILES)
        if form.is_valid():
            document = form.save(commit=False)
            document.uploaded_by = request.user
            if document.portfolio in request.user.userprofile.portfolios.all():
                document.save()
                return redirect('document_list')
            else:
                form.add_error('portfolio', "You don't have permission to upload to this portfolio.")
    else:
        form = DocumentForm()
    return render(request, 'documents/upload_document.html', {'form': form})

@login_required
def edit_document(request, document_id):
    document = get_object_or_404(Document, id=document_id)

    if request.method == "POST":
        form = DocumentForm(request.POST, request.FILES, instance=document)

        if form.is_valid():
            if 'file' in request.FILES:  # If a new file is uploaded
                old_version = DocumentVersion.objects.create(
                    document=document,
                    file=document.file,  # Store old file before updating
                    version_number=document.versions.count() + 1
                )
                old_version.save()

            form.save()
            return redirect('document_list')

    else:
        form = DocumentForm(instance=document)

    return render(request, 'documents/edit_document.html', {'form': form, 'document': document})

@login_required
def document_versions(request, document_id):
    document = get_object_or_404(Document, id=document_id)
    versions = document.versions.all().order_by('-uploaded_at')

    return render(request, 'documents/document_versions.html', {'document': document, 'versions': versions})

@login_required
def create_folder(request):
    """ Create a new folder dynamically via AJAX request. """
    if request.method == "POST":
        folder_form = FolderForm(request.POST)
        if folder_form.is_valid():
            new_folder = folder_form.save(commit=False)
            new_folder.created_by = request.user
            new_folder.save()
            return redirect('document_list')
    
    return render(request, 'documents/create_folder.html', {'folder_form': folder_form})


@login_required
def edit_folder(request, folder_id):
    """ Edit folder name """
    folder = get_object_or_404(Folder, id=folder_id)

    if request.method == "POST":
        new_name = request.POST.get("folder_name", "").strip()  # Get name and remove extra spaces

        if new_name:  # Ensure the name is not empty
            folder.name = new_name
            folder.save()
            return redirect('document_list')
        else:
            return render(request, 'documents/edit_folder.html', {'folder': folder, 'error': "Folder name cannot be empty!"})

    return render(request, 'documents/edit_folder.html', {'folder': folder})

def get_file_icon(file_name):
    """Returns the appropriate FontAwesome class for the given file type"""
    file_name = file_name.lower()
    
    if file_name.endswith('.pdf'):
        return "fas fa-file-pdf text-danger"
    elif file_name.endswith(('.doc', '.docx')):
        return "fas fa-file-word text-primary"
    elif file_name.endswith(('.xls', '.xlsx')):
        return "fas fa-file-excel text-success"
    elif file_name.endswith(('.ppt', '.pptx')):
        return "fas fa-file-powerpoint text-warning"
    elif file_name.endswith(('.zip', '.rar')):
        return "fas fa-file-archive text-secondary"
    elif file_name.endswith('.py'):
        return "fas fa-file-code text-success"
    else:
        return "fas fa-file"

def get_file_icon(file_name):
    """Returns the appropriate FontAwesome class for the given file type"""
    file_name = file_name.lower()

    if file_name.endswith('.pdf'):
        return "fas fa-file-pdf text-danger"
    elif file_name.endswith(('.doc', '.docx')):
        return "fas fa-file-word text-primary"
    elif file_name.endswith(('.xls', '.xlsx')):
        return "fas fa-file-excel text-success"
    elif file_name.endswith(('.ppt', '.pptx')):
        return "fas fa-file-powerpoint text-warning"
    elif file_name.endswith(('.zip', '.rar')):
        return "fas fa-file-archive text-secondary"
    elif file_name.endswith('.py'):
        return "fas fa-file-code text-success"
    else:
        return "fas fa-file"

def get_file_icon(file_name):
    """Returns the appropriate FontAwesome class for the given file type"""
    file_name = file_name.lower()

    if file_name.endswith('.pdf'):
        return "fas fa-file-pdf text-danger"
    elif file_name.endswith(('.doc', '.docx')):
        return "fas fa-file-word text-primary"
    elif file_name.endswith(('.xls', '.xlsx')):
        return "fas fa-file-excel text-success"
    elif file_name.endswith(('.ppt', '.pptx')):
        return "fas fa-file-powerpoint text-warning"
    elif file_name.endswith(('.zip', '.rar')):
        return "fas fa-file-archive text-secondary"
    elif file_name.endswith('.py'):
        return "fas fa-file-code text-success"
    else:
        return "fas fa-file"

@login_required
def document_list(request):
    """ Display folders, documents, handle uploads, and folder creation """

    # Get selected portfolio filter
    selected_portfolio_id = request.GET.get('portfolio')

    if request.user.is_superuser:
        folders = Folder.objects.all()
        documents = Document.objects.all()
        portfolios = Portfolio.objects.all()
    else:
        user_profile = UserProfile.objects.filter(user=request.user).first()
        if user_profile:
            user_portfolios = user_profile.portfolios.all()

            # Filter documents by user portfolio
            documents = Document.objects.filter(portfolio__in=user_portfolios)

            # Fetch folders that contain documents the user has access to
            folder_ids = documents.values_list('folder_id', flat=True)
            folders = Folder.objects.filter(Q(id__in=folder_ids) | Q(parent__in=folder_ids)).distinct()

            portfolios = Portfolio.objects.filter(
                Q(id__in=user_portfolios.values_list('id', flat=True)) |
                Q(id__in=documents.values_list('portfolio_id', flat=True))
            ).distinct()
        else:
            folders = Folder.objects.none()
            documents = Document.objects.none()
            portfolios = Portfolio.objects.none()

    # Apply portfolio filter
    if selected_portfolio_id:
        documents = documents.filter(portfolio_id=selected_portfolio_id)
        folders = folders.filter(id__in=documents.values_list('folder_id', flat=True))

    # Assign file icons
    for document in documents:
        document.icon_class = get_file_icon(document.file.name)

    folder_form = FolderForm()
    doc_form = DocumentForm()

    if request.method == "POST":
        if "create_folder" in request.POST:
            folder_form = FolderForm(request.POST)
            if folder_form.is_valid():
                new_folder = folder_form.save(commit=False)
                new_folder.created_by = request.user
                new_folder.save()
                return redirect('document_list')

        if "upload_document" in request.POST:
            doc_form = DocumentForm(request.POST, request.FILES)
            if doc_form.is_valid():
                new_doc = doc_form.save(commit=False)
                new_doc.uploaded_by = request.user
                new_doc.save()
                return redirect('document_list')

    return render(request, 'documents/document_list.html', {
        'folders': folders,
        'documents': documents,
        'portfolios': portfolios.order_by('name'),
        'folder_form': folder_form,
        'doc_form': doc_form,
        'selected_portfolio_id': selected_portfolio_id,
    })

@login_required
def delete_folder(request, folder_id):
    """ Delete a folder and all its contents (subfolders & files) """
    folder = get_object_or_404(Folder, id=folder_id)

    # Check if the folder has any files or subfolders
    if folder.subfolders.exists() or Document.objects.filter(folder=folder).exists():
        return JsonResponse({"error": "Cannot delete non-empty folder"}, status=400)

    folder.delete()
    return JsonResponse({"success": "Folder deleted successfully"})

@login_required
def delete_document(request, document_id):
    """ Delete a document """
    document = get_object_or_404(Document, id=document_id)
    document.delete()
    return redirect('document_list')

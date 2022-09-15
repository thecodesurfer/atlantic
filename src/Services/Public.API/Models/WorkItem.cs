namespace Atlantic.Services.Public.API.Models;

#nullable disable
public class WorkItem : BaseEntity
{
    public string Title { get; set; }
    public string Description { get; set; }

    public WorkItemState State { get; set; }
    public WorkItemType Type { get; set; }

    public WorkItem Parent { get; set; }
    public WorkItem SubItems { get; set; }
}
#nullable enable

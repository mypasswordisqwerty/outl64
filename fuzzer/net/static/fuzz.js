
$(document).ready(function() {

    var states = [{"id":0, "name":""},{"id":1, "name":"Reload"},{"id":2, "name":"Update"}];

    function changeState(state){
        $.ajax({
            type: "PUT", 
            url: "/client", 
            data: '{"ID":"all", "State":"'+state+'"}',
            complete: function(data) {
                $("#clients").jsGrid("loadData");
            }
        });
    }

    $('#clients').jsGrid({
        width: "100%",
        height: "auto",
 
        editing: true,
        sorting: false,
        paging: true,
        autoload: true,

        pageSize: 25,
        pageButtonCount: 5,
 
        controller: {
            loadData: function(filter) {
                return $.ajax({type: "GET", url: "/client", data: filter});
            },
            updateItem: function(item) {
                return $.ajax({type: "PUT", url: "/client", data: item});
            },
            deleteItem: function(item) {
                return $.ajax({type: "DELETE", url: "/client", data: item});
            },
        },
 
        fields: [
            { name: "ID", type: "text", width: 10, editing: false},
            { name: "Name", type: "text", width: 50, editing: false},
            { name: "Ver", type: "text", width: 10, editing: false},
            { name: "IP", type: "text", width: 50, editing: false},
            { name: "Job", type: "text", width: 50, editing: false},
            { name: "Progress", type: "text", width: 50, editing: false},
            { name: "State", type: "select", items: states, valueField: "id", textField: "name", width: 50,
                headerTemplate: function() {
                    return [$("<button>").attr("type", "button").text("Update all")
                            .on("click", function () {
                                changeState(2);
                            }), $("<button>").attr("type", "button").text("Reload all")
                            .on("click", function () {
                                changeState(1);
                            })];
                },
            },
            { name: "Online", type: "text", editing: false,
                itemTemplate: function(_, item) {
                    return item.Active ? item.Online : '<span class="offline">'+item.Online+'</span>'
                },
            },
            { type: "control"}
        ]
    });


    $('#jobs').jsGrid({
        width: "100%",
        height: "auto",
 
        inserting: true,
        editing: true,
        paging: true,
        autoload: true,
 
        controller: {
            loadData: function(filter) {
                return $.ajax({type: "GET", url: "/job", data: filter});
            },
            insertItem: function(item) {
                return $.ajax({type: "POST", url: "/job", data: item});
            },
            updateItem: function(item) {
                return $.ajax({type: "PUT", url: "/job", data: item});
            },
            deleteItem: function(item) {
                return $.ajax({type: "DELETE", url: "/job", data: item});
            },
        },
 
        fields: [
            { name: "Name", type: "text", width: 50 },
            { name: "Task", type: "text"},
            { type: "control" }
        ]
    });
} );

